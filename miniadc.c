/*
 *
 *  MiniADC : a minimal implementation of the ADC protocol
 *  Copyright (c) 2012 Lorenzo Keller
 *
 *
 */

#include <assert.h>

#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include "tiger/tiger.h"
#include <libgen.h>
#include <dirent.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <bzlib.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>

#define MAX_STR_LEN 1500
#define HASH_LEN 24
#define HASH_LEN_B32 40
#define SID_LEN 5

#define CHARS_FOR_LONG (CHAR_BIT * sizeof(long) / 3) + 2
#define CHARS_FOR_INT (CHAR_BIT * sizeof(int) / 3) + 2

typedef struct _tth_t {
	char hash[HASH_LEN];
	struct _tth_t *next_sibling;
} tth_t;

typedef struct _file_t {
	char root_tth[HASH_LEN];
	char *name;
	long size;
	struct _file_t *next;
	struct _dir_t* parent;
	char *fullpath;
	char *index_pos;
	time_t last_change;
} file_t;

typedef struct _dir_t {
	char *name;
	struct _dir_t *parent;
	file_t *first_file;
	struct _dir_t *first_subdir;
	struct _dir_t *next;
} dir_t;

typedef struct _peer_t {
	char sid[SID_LEN];
	struct in_addr addr4;
	char cid[HASH_LEN_B32];
	char *nick;
	struct _peer_t *next;
} peer_t;

typedef struct _context_t {
	int sd;
	gnutls_session_t session;
	int state;
	struct {
		int tigr;
		int base;
		int ping;
	} features;
	char sid[SID_LEN];
	char cid[HASH_LEN_B32];
	char pid[HASH_LEN_B32];
	char* nickname;
	char* password;
	dir_t *root_dir;
	peer_t *first_peer;
	char *root_path;
} context_t;


enum {
	STATE_PROTOCOL,
	STATE_IDENTIFY,
	STATE_VERIFY,
	STATE_NORMAL,
	STATE_DATA
};

int send_message( context_t* ctx, char* message );

static int _verify_certificate_callback (gnutls_session_t session);

void destroy_peer(peer_t *peer) {
	if (peer->nick != NULL) free(peer->nick);
}

peer_t *create_peer(char *sid, char* cid, char* nick, struct in_addr* addr4) {

	peer_t *peer = (peer_t *) malloc(sizeof(peer_t));

	strcpy(peer->sid, sid);
	strcpy(peer->cid, cid);

	if (nick != NULL) {
		peer->nick = (char *) malloc(strlen(nick) + 1);
		strcpy(peer->nick, nick);
	}

	peer->addr4.s_addr = addr4->s_addr;

	peer->next = NULL;

	return peer;

}

tth_t *create_tth(char *data, int len) {

	tth_t *tth = (tth_t *) malloc(sizeof(tth_t));

	tth->next_sibling = NULL;

	char data2[len + 1];

	data2[0] = 0x00;
	memcpy(data2 + 1, data, len);

	tiger((uint64_t *) data2, len + 1, (uint64_t *) tth->hash);

	return tth;

}


tth_t *merge_tth(tth_t *left, tth_t *right) {

	tth_t* tth = (tth_t *) malloc(sizeof(tth_t));

	tth->next_sibling = NULL;

	char data[HASH_LEN * 2 + 1];

	data[0] = 0x01;
	memcpy(data + 1, left, HASH_LEN);
	memcpy(data + HASH_LEN + 1, right, HASH_LEN);

	tiger((uint64_t *) data, HASH_LEN * 2 + 1, (uint64_t *) tth->hash);

	return tth;

}

tth_t *create_tth_level_from_level(tth_t *first_lower_layer) {

	tth_t *first_new_layer = NULL;
	tth_t *last_new_layer = NULL;

	tth_t *next_lower_layer = first_lower_layer;

	while ( next_lower_layer != NULL && next_lower_layer->next_sibling != NULL ) {

		tth_t *next_tth = merge_tth(next_lower_layer, next_lower_layer->next_sibling);

		if ( first_new_layer == NULL) {
			first_new_layer = next_tth;
		} else {
			last_new_layer->next_sibling = next_tth;
		}

		last_new_layer = next_tth;

		next_lower_layer = next_lower_layer->next_sibling->next_sibling;

	}

	/* copy the spare leaf to the current level */
	if ( next_lower_layer != NULL) {
		tth_t* new_tth = (tth_t*) malloc( sizeof(tth_t));
		new_tth->next_sibling = NULL;
		memcpy(new_tth->hash, next_lower_layer->hash, HASH_LEN);

		if (first_new_layer == NULL) {
			first_new_layer = new_tth;
		} else {
			last_new_layer->next_sibling = new_tth;
		}
	}

	return first_new_layer;

}

void destroy_tth_level(tth_t *first) {

	while ( first != NULL ) {
		tth_t *temp = first;
		first = temp->next_sibling;
		free(temp);
	}

}

tth_t *create_tth_level_from_buffer(char *buf, int block_size) {

	tth_t *first_tth = NULL;
	tth_t *last_tth = NULL;

	int remaining = block_size;
	char *next_block = buf;

	while (remaining > 0 || first_tth == NULL) {

		int len = 1024;

		if ( remaining < 1024) {
			len = remaining;
		}

		tth_t *next_tth = create_tth(next_block, len);

		if (last_tth != NULL) {
			last_tth->next_sibling = next_tth;
		} else {
			first_tth = next_tth;
		}

		last_tth = next_tth;

		next_block = next_block + len;
		remaining -= len;
	}

	return first_tth;

}

tth_t *create_subtree(char *buf, int block_size) {

	tth_t *first = create_tth_level_from_buffer(buf, block_size);

	while ( first->next_sibling != NULL) {

		tth_t *new_first = create_tth_level_from_level(first);
		destroy_tth_level(first);
		first = new_first;
	}

	return first;

}



int compute_tth(file_t *file) {

	FILE *index = fopen(file->index_pos, "r");

	if ( index != NULL) {
		time_t t;
		if ( fread(&t, sizeof(time_t), 1, index) == 1) {
			if ( t == file->last_change) {
				if ( fread(file->root_tth, HASH_LEN, 1, index) == 1) {
					fclose(index);
					return 0;
				}

			}
		}

		fclose(index);
	}

	printf("Hashing file %s\n", file->fullpath);

	FILE *f = fopen(file->fullpath, "r");

	if (f == NULL) {
		return -1;
	}	

	int len;

	long total_block = (file->size + 1023l) / 1024l;

	// a zero length file has one block
	if ( total_block == 0) {
		total_block = 1;
	}

	/* compute the number of levels */
	int total_levels = 1;
	while ( total_block > ( 1 << ( total_levels - 1))) {
		total_levels++;
	}

	/* compute the block size */
	int levels_to_compress = total_levels - 7;
	if ( levels_to_compress > 0) {

		/* we can compress at most 6 levels to obtain hashes of 64KiB */
		if ( levels_to_compress > 6) {
			levels_to_compress = 6;
		}
	} else {
		levels_to_compress = 0;
	}

	int block_size = (1 << levels_to_compress) * 1024;

	tth_t *first_tth = NULL;
	tth_t *last_tth = NULL;

	char buf[block_size];
	char *ptr;

	while (1) {

		int read = 0;
		ptr = buf;

		do {
			len = fread(ptr, 1, block_size - read, f);
			read += len;
			ptr += len;
		} while ( read < block_size && len != 0);

		// we are at the end of the file and at least one leaf exists
		if ( read == 0 && last_tth != NULL) {
			break;
		}

		tth_t *next_tth = create_subtree(buf, read);

		if (last_tth != NULL) {
			last_tth->next_sibling = next_tth;
		} else {
			first_tth = next_tth;
		}

		last_tth = next_tth;

	}

	fclose(f);

	tth_t *next_level = create_tth_level_from_level(first_tth);

	while ( next_level->next_sibling != NULL) {

		tth_t *new_first = create_tth_level_from_level(next_level);
		destroy_tth_level(next_level);
		next_level = new_first;
	}

	memcpy(file->root_tth, next_level->hash, HASH_LEN);

	destroy_tth_level(next_level);

	/* save the tthl in the index file */

	index = fopen(file->index_pos, "w");

	if ( index == NULL) {
		return -1;
	}

	fwrite(&(file->last_change), sizeof(time_t), 1, index);
	fwrite(file->root_tth, HASH_LEN, 1, index);

	tth_t* next_tth = first_tth;

	while ( next_tth != NULL ) {
		fwrite(next_tth->hash, HASH_LEN, 1, index);
		next_tth = next_tth->next_sibling;
	}

	fclose(index);

	destroy_tth_level(first_tth);

	return 0;
}

char *strreplace(char *haystack, char *needle, char *replace) {

	char *output = (char *) malloc(1);
	output[0] = 0;
	int output_len = 0;

	int replace_len = strlen(replace);
	int needle_len = strlen(needle);

	char *after_last_needle = haystack;
	char *beginning_of_next_needle;

	while ( (beginning_of_next_needle = strstr(after_last_needle, needle)) != NULL ) {

		int token_len = beginning_of_next_needle - after_last_needle;

		char *new_output = (char*) malloc(output_len + token_len + replace_len + 1);

		memcpy(new_output, output, output_len);
		memcpy(new_output + output_len, after_last_needle, token_len);
		memcpy(new_output + output_len + token_len, replace, replace_len);
		new_output[output_len + token_len + replace_len] = 0;

		free(output);
		output = new_output;

		after_last_needle = beginning_of_next_needle + needle_len;
		output_len = output_len + token_len + replace_len;

	}

	if ( after_last_needle != NULL) {

		int token_len = strlen(after_last_needle);
		char *new_output = (char*) malloc(output_len + token_len + 1);

		memcpy(new_output, output, output_len);
		memcpy(new_output + output_len, after_last_needle, token_len);
		new_output[output_len + token_len] = 0;

		free(output);
		output = new_output;
	}

	return output;

}

file_t* index_file(char *path, char* index_dir) {

	file_t *f = (file_t *) malloc(sizeof(file_t));

	char cp[strlen(path) + 1];

	strcpy(cp, path);

	char *name = basename(cp);

	f->name = (char*) malloc(strlen(name) + 1);
	strcpy(f->name, name);

	f->fullpath = (char *) malloc(strlen(path) + 1);
	strcpy(f->fullpath, path);

	struct stat s;

	if ( stat(path, &s) < 0 ) {
		free(f);
		return NULL;
	}

	f->size = s.st_size;
	f->index_pos = 0;
	f->last_change = s.st_mtim.tv_sec;


	f->index_pos = (char *) malloc( strlen(index_dir) +  1 + strlen(name) + 1 );
	sprintf(f->index_pos, "%s/%s", index_dir, name);

	if ( compute_tth(f) < 0) {
		free(f->index_pos);
		free(f->name);
		free(f->fullpath);
		free(f);
		return NULL;
	}

	return f;

}

dir_t* index_directory(char *path, char* index_dir) {

	dir_t *d = (dir_t*) malloc(sizeof(dir_t));
	
	char cp[strlen(path) + 1];
	strcpy(cp, path);

	char *name = basename(cp);

	d->name = (char*) malloc(strlen(name) + 1);
	strcpy(d->name, name);

	d->first_file = NULL;
	d->first_subdir = NULL;
	d->next = NULL;

	DIR* dir = opendir(path);

	if (dir == NULL) {
		printf("Cannot find directory %s\n", path);
		free(d->name);
		free(d);
		return NULL;
	}

	mkdir(index_dir, S_IRUSR | S_IWUSR | S_IXUSR);

	struct dirent *e;
	
	while ( (e = readdir(dir)) != NULL) {

		if ( strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
			continue;
		}

		char fpath[strlen(path) + 1 + strlen(e->d_name)];		

		sprintf(fpath, "%s/%s", path, e->d_name);

 		struct stat s;

		if ( stat(fpath, &s) < 0 ) {
			continue;
		}
		
		if ( S_ISREG(s.st_mode) ) {

			file_t *f = index_file(fpath, index_dir);
			
			if ( f != NULL) {
				f->parent = d;
				f->next = d->first_file;
				d->first_file = f;
			}
		} else if ( S_ISDIR(s.st_mode) ) {

			char sub_index[strlen(index_dir) + 1 + strlen(e->d_name) + 1];

			sprintf(sub_index, "%s/%s", index_dir, e->d_name);

			dir_t *subdir = index_directory(fpath, sub_index);

			if ( subdir != NULL) {
				subdir->next = d->first_subdir;
				d->first_subdir = subdir;
				d->parent = d;
			}
		}


	}

	closedir(dir);

	return d;

}


char *remove_adc_escapes(char* str) {

	char *pass1 = strreplace(str, "\\s", " ");

	char *pass2 = strreplace(pass1, "\\n", "\n");

	free(pass1);

	char *pass3 = strreplace(pass2, "\\\\", "\\");

	free(pass2);

	return pass3;

}

char *escape_adc(char *str) {

	char *pass1 = strreplace(str, "\\", "\\\\");
	char *pass2 = strreplace(pass1, "\n", "\\n");
	char *pass3 = strreplace(pass2, " ", "\\s");

	free(pass2);
	free(pass1);

	return pass3;
}


char *escape_xml(char *name) {

	char *pass1 = strreplace(name, "&", "&amp;");
	char *pass2 = strreplace(pass1, "<", "&lt;");
	free(pass1);

	return pass2;
}

int skip_unknown_message(context_t *ctx) {

	while ( 1 ) {
		char ch = 0;

		int ret;

		ret = gnutls_record_recv (ctx->session, &ch, 1);

		if ( ret < 0 ) {
			fprintf (stderr, "Error: %s\n", gnutls_strerror (ret));
			return -1;
		} else if ( ret == 0 ) {
			printf ("Peer has closed the TLS connection\n");
			return -1;
		}
		
		if ( ch == '\n' ) return 0;
	}

	// just because eclipse complains
	return 0;
}

int read_message_from_client(int fd, char *data, int len) {

	int ret;

	int idx = 0;

	memset(data, 0, len);

	while ( idx < len ) {

		ret = recv (fd, data + idx, 1, 0);

		if ( ret < 0 ) {
			return -1;
		} else if ( ret == 0 ) {
			printf ("Peer has closed connection\n");
			return -1;
		}

		if ( data[idx] == '\n' ) {
			data[idx] = 0;
			return 0;
		}

		idx++;

	}

	if (idx == len) {
		printf ("Received message too long\n");
                return -1;
	}

	return 0;
}


int read_message(context_t *ctx, char *data, int len) {

	int ret;

	int idx = 0;

	memset(data, 0, len);

	while ( idx < len ) {
			
		ret = gnutls_record_recv (ctx->session, data + idx, 1);

		if ( ret < 0 ) {
			fprintf (stderr, "Error: %s\n", gnutls_strerror (ret));
			return -1;
		} else if ( ret == 0 ) {
			printf ("Peer has closed the TLS connection\n");
			return -1;
		}

		if ( data[idx] == '\n' ) {
			return 0;
		}

		idx++;

	}

	if (idx == len) {
		printf ("Received message too long\n");
                return -1;
	}

	return 0;
}

int b32_decode(char *str_base32, char *bin, int maxlen) {

	unsigned int carry = 0;
	int carry_len = 0;

	int idx = 0;
	int i = 0;

	unsigned char *base32 = (unsigned char*) str_base32;

	while (1) {
		
		unsigned int v;
		if ( base32[i] == '='  || base32[i] == 0 ) {
			break;
		} else if ( base32[i] >= 'A' && base32[i] <= 'Z' ) {
			v = base32[i] - 'A';
		} else {
			v = base32[i] - '2' + 26;	
		}

		carry = (carry << 5) | v ;
		carry_len += 5;

		if (carry_len >= 8) {

			if ( idx == maxlen) {
				return maxlen;
			}

			bin[idx] = carry >> ( carry_len - 8 );
			carry_len = carry_len - 8;
			idx++;
		}
		i++;
	}	
	
	if ( carry_len > 0 ) {
		if ( idx == maxlen) {
			return maxlen;
		}
		carry = (carry << (8 - carry_len) ) & 0xFF;
		bin[idx] = carry;
		idx++;
	}

	return idx - 1;

}

int b32_encode(char *bin, int len, char* base32, int maxlen) {
	int i;

	unsigned int carry = 0;
	int carry_len = 0;
	int idx = 0;
	for (i = 0 ; i < len ; i++) {
		int ch = bin[i] & 0xFF;
		
		carry = ( carry << 8 ) | ch;
		carry_len = carry_len + 8;

		while ( carry_len >= 5 ) {

			if ( idx == maxlen ) return maxlen;

			int v = (carry >> ( carry_len - 5)) % 32;
			if ( v < 26 ) {
				base32[idx] = 'A' + v;
			} else {
				base32[idx] = '2' + ( v - 26);
			}
			carry_len = carry_len - 5;	
			idx++;
		}
	}

	if ( carry_len > 0 ) {
			carry = carry << ( 5 - carry_len);
			int v = carry % 32;
			if ( idx == maxlen ) return maxlen;
			if ( v < 26 ) {
				base32[idx] = 'A' + v;
			} else {
				base32[idx] = '2' + ( v - 26);
			}
			idx++;
	}

	int padding = 0;

	if ( (len * 8) % 40 == 8 ) {
		padding = 6;	
	} else if ( (len * 8) % 40 == 16) {
		padding = 4;
	} else if ( (len * 8) % 40 == 24 ) {
		padding = 3;
	} else if ( (len * 8) % 40 == 32 ) {
		padding = 1;
	}

	for ( i = 0 ; i < padding ; i++) {
		if ( idx == maxlen ) return maxlen;
		base32[idx] = '=';
		idx++;
	}

	if ( idx == maxlen ) return maxlen;
	base32[idx] = 0;
	return idx;
}

void decode_hash(char *b32_hash, char *dest) {

	char b32[HASH_LEN_B32 + 1];

	memcpy(b32, b32_hash, HASH_LEN_B32);
	b32[HASH_LEN_B32 - 1] = '=';
	b32[HASH_LEN_B32] = 0;

	b32_decode(b32, dest, HASH_LEN);

}

char *b32_hash(char* hash) {
	static char b32[HASH_LEN_B32 + 1];

	b32_encode(hash, HASH_LEN, b32, HASH_LEN_B32 + 1);
	b32[HASH_LEN_B32 - 1 ] = 0;

	return b32;
}

void create_pid(char* b32_pid) {

	char *format = "miniadc%dl";

	char data[strlen(format) + CHARS_FOR_LONG + 1];

	sprintf(data, format, time(NULL));

	char pid[HASH_LEN];
	
	tiger((uint64_t *) data, sizeof(data), (uint64_t *) pid);

	char full_pid[HASH_LEN_B32 + 1];
	b32_encode(pid, HASH_LEN, full_pid, HASH_LEN_B32 + 1);

	// we discard the padding symbol
	full_pid[HASH_LEN_B32 - 1] = 0;

	strcpy(b32_pid, full_pid);
}

void create_cid(char* b32_pid, char* b32_cid) {

	/* first we need to decode the pid */

	char full_pid[HASH_LEN_B32 + 1];
	char pid[HASH_LEN];

	// we add back the padding symbol
	memcpy(full_pid, b32_pid, HASH_LEN_B32);
	full_pid[HASH_LEN_B32 - 1 ] = '=';
	full_pid[HASH_LEN_B32] = 0;

	b32_decode(full_pid, pid, HASH_LEN);

	char cid[HASH_LEN];

	tiger((uint64_t *) pid, HASH_LEN, (uint64_t *) cid);

	char full_cid[HASH_LEN_B32 + 1];
	b32_encode(cid, HASH_LEN, full_cid, HASH_LEN_B32 + 1);
	
	// we discard the padding symbol
	full_cid[HASH_LEN_B32 - 1] = 0;
	
	strcpy(b32_cid, full_cid);

}
int create_password(char *b32_gpa, char *password, char *token) {
	
	int b32_gpa_len = strlen(b32_gpa);
	int gpa_len = b32_gpa_len * 5 / 8 + 8;

	char gpa[gpa_len];

	gpa_len = b32_decode(b32_gpa, gpa, gpa_len);

	int password_len = strlen(password);

	int total_len = password_len + gpa_len; 

	char a[total_len];

	strcpy(a, password);
	memcpy(a + password_len, gpa, gpa_len);

	char hash[HASH_LEN];

	tiger((uint64_t *) a, total_len, (uint64_t *) hash);

	char b32_hash[HASH_LEN_B32 + 1];
	b32_encode(hash, HASH_LEN, b32_hash, HASH_LEN_B32 + 1); 

	b32_hash[HASH_LEN_B32 - 1] = 0;
	strcpy(token, b32_hash);


	return 0;
}

void tiger_tree_hash_ex(char* data, int len, char* hash, int type) {

	int len64 = (len + 1) / 8;

	if ((len + 1) % 8 != 0 ) {
		len64++;
	} 

	uint64_t data64[len64];

	memset(data64, 0, len64);

	((char *) data64)[0] = type;

	memcpy(((char *)data64) + 1, data, len);	

	char hashdata[3 * 8];

	uint64_t *binary_hash = (uint64_t*) (hashdata );

	tiger(data64, len64, binary_hash);

	b32_encode((char *) hashdata, sizeof(hashdata), hash, 41);
	
	// we discard the padding symbol
	hash[39] = 0;

}


int send_message_to_client( int fd, char* message ) {
	int ret;
	ret = send(fd, message, strlen (message), 0);

	if ( ret < 0 ) {
			perror("Error while sending");
			return -1;
	}

	return 0;
}

char* append(char *one, char* other) {

	char *out = (char *) malloc( strlen(one) + strlen(other) + 1);

	strcpy(out, one);
	strcat(out, other);

	return out;
}

char *create_file_list(file_t *f) {

	char *outer = "<File Name=\"%s\" Size=\"%ld\" TTH=\"%s\" />\n";


	char tth[HASH_LEN_B32 + 1];

	b32_encode(f->root_tth, HASH_LEN, tth, HASH_LEN_B32 + 1);

	tth[HASH_LEN_B32 - 1] = 0;

	char *name_xml = escape_xml(f->name);

	char *out = (char *) malloc(strlen(outer) + strlen(name_xml) + HASH_LEN_B32 + CHARS_FOR_LONG + 1);

	sprintf(out, outer, name_xml, f->size, tth);

	free(name_xml);

	return out;

}

char *create_dir_list(dir_t *dir) {

	char *outer = "<Directory Name=\"%s\">\n%s\n</Directory>\n";

	char *body = (char *) malloc(1);

	body[0] = 0;

	dir_t * subdir = dir->first_subdir;

	while (subdir != NULL ) {

		char *subdir_txt = create_dir_list(subdir);

		char *new_body = append(body, subdir_txt);

		free(body);
		free(subdir_txt);

		body = new_body;
		subdir = subdir->next;
	}

	file_t * file = dir->first_file;

	while (file != NULL ) {

		char *file_txt = create_file_list(file);

		char *new_body = append(body, file_txt);

		free(body);
		free(file_txt);

		body = new_body;
		file = file->next;
	}

	char *name_xml = escape_xml(dir->name);

	char *out = (char *) malloc( strlen(outer) + strlen(body) + strlen(name_xml) + 1);

	sprintf(out, outer, name_xml, body);

	free(name_xml);

	return out;

}

char *create_complete_list(context_t *ctx) {


	char *outer = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n" \
				 "<FileListing Version=\"1\" CID=\"%s\" Generator=\"miniadc 0.1\" Base=\"/\">\n" \
				 "%s" \
				 "</FileListing>";

	char *dirlist = create_dir_list(ctx->root_dir);

	char *out = (char*) malloc(strlen(outer) + strlen(dirlist) + HASH_LEN_B32 + 1);

	sprintf(out, outer, ctx->cid, dirlist);

	return out;
}

int send_files_list(context_t *ctx, int fd) {

	printf("Creating file list...\n");

	char *list = create_complete_list(ctx);

	char *out = (char *) malloc(strlen(list));
	unsigned int out_len = strlen(list);

	printf("Compressing file list...\n");

	if ( BZ2_bzBuffToBuffCompress(out, &out_len, list, strlen(list), 1, 0, 0) != BZ_OK ) {
		printf("Error while compressing file list\n");
		return -1;
	}

	char *format = "CSND file files.xml.bz2 0 %d\n";

	char message[strlen(format) + CHARS_FOR_INT + 1];

	sprintf(message, format, out_len);

	printf("Sending file list...\n");

	send_message_to_client(fd, message);

	send(fd, out, out_len, 0);

	printf("File list sent\n");

	return 0;

}

peer_t *find_peer(context_t *ctx, char* sid) {

	peer_t *out = ctx->first_peer;

	while ( out != NULL) {
		if ( strcmp(sid, out->sid) == 0 ) {
			return out;
		}
		out = out->next;
	}

	return NULL;
}

file_t *find_file_with_hash(dir_t *dir, char* tth) {

	file_t *file = dir->first_file;

	while (file != NULL) {
		if ( memcmp(file->root_tth, tth, HASH_LEN) == 0) {
			return file;
		}
		file = file->next;
	}

	dir_t *subdir = dir->first_subdir;

	while ( subdir != NULL ) {
		file = find_file_with_hash(subdir, tth);

		if (file != NULL) {
			return file;
		}

		subdir = subdir->next;
	}

	return NULL;

}

tth_t *load_tthl(file_t *file) {


	FILE *index = fopen(file->index_pos, "r");

	if ( index == NULL) {
		return NULL;
	}

	time_t t;

	if ( fread(&t, sizeof(time_t), 1, index) != 1) {
		fclose(index);
		return NULL;
	}

	char root_hash[HASH_LEN];

	if ( fread(&root_hash, HASH_LEN, 1, index) != 1) {
		fclose(index);
		return NULL;
	}

	tth_t *first = NULL;
	tth_t *last = NULL;

	char hash[HASH_LEN];

	while ( (fread(hash, HASH_LEN, 1, index ) == 1)) {

		tth_t *next = (tth_t *) malloc(sizeof(tth_t));

		memcpy(next->hash, hash, HASH_LEN);
		next->next_sibling = NULL;

		if ( first == NULL) {
			first = next;
		} else {
			last->next_sibling = next;
		}

		last = next;

	}

	fclose(index);

	return first;

}

int send_tth_list(context_t* ctx, int fd, char* file_hash, long start_pos, long bytes) {

	if ( strlen(file_hash) != 4 + HASH_LEN_B32 - 1) {
		return -1;
	}

	char b32_hash[HASH_LEN_B32+1];
	strcpy(b32_hash, file_hash+4);
	b32_hash[HASH_LEN_B32 - 1] = '=';
	b32_hash[HASH_LEN_B32 - 1] = '0';
	char tth[HASH_LEN];
	b32_decode(b32_hash, tth, HASH_LEN);

	file_t *file = find_file_with_hash(ctx->root_dir, tth);

	if  (file ==  NULL) {
		send_message_to_client(fd, "CSTA 151 file\\snot\\savailable\n");
		printf("File not found\n");
		return -1;
	}

	// find the first leaf tth
	tth_t *ptth = load_tthl(file);

	// count the number of leaves
	int leaf_count = 1;
	tth_t *next_ptth = ptth;
	while ( next_ptth->next_sibling != NULL) {
		leaf_count ++;
		next_ptth = next_ptth->next_sibling;
	}

	long out_len;

	if ( bytes == -1) {
		out_len = leaf_count * HASH_LEN;
	} else {
		out_len = bytes;
	}

	char *format = "CSND tthl %s %ld %ld\n";

	char message[strlen(format) +  strlen(file_hash) + 2 * CHARS_FOR_LONG + 1];

	sprintf(message, format, file_hash, start_pos, out_len);

	send_message_to_client(fd, message);

	long offset = 0;

	do {
		if (start_pos <= offset) {
			send(fd, ptth->hash, HASH_LEN, 0);
		} else {
			if ( start_pos - HASH_LEN < offset) {
				send(fd, ptth->hash + ( start_pos - offset ), HASH_LEN - ( start_pos - offset ), 0);
			}
		}
		offset += HASH_LEN;
		ptth = ptth->next_sibling;
	} while (ptth != NULL);

	destroy_tth_level(ptth);

	return 0;

}


int send_file(context_t *ctx, int fd, char* file_name, long start_pos, long bytes) {

	if ( strncmp(file_name, "TTH/", 4) == 0 ) {

		char b32_hash[HASH_LEN_B32 + 1];

		strcpy(b32_hash, file_name + 4);
		b32_hash[HASH_LEN_B32] = 0;
		b32_hash[HASH_LEN_B32 - 1] = '=';

		char hash[HASH_LEN];

		b32_decode(b32_hash, hash, HASH_LEN);

		file_t *f = find_file_with_hash(ctx->root_dir, hash);

		if ( f == NULL) {
			printf("Cannot find file with hash %s", file_name);
			return -1;
		}

		FILE *f2 = fopen(f->fullpath, "r");

		if ( f2 == NULL) {
			printf("Unable to open file %s\n",f->fullpath);
			return -1;
		}

		if ( fseek(f2, start_pos, SEEK_SET) < 0 ) {
			printf("Unable to seek file %s to position %ld\n",f->fullpath, start_pos );
			fclose(f2);
			return -1;
		}

		char *format = "CSND file %s %ld %ld\n";

		char message[strlen(format) + strlen(file_name) + 2 * CHARS_FOR_LONG + 1];

		sprintf(message, format, file_name, start_pos, bytes);

		send_message_to_client(fd, message);

		char buf[1500];
		int remaining = bytes;

		while ( remaining > 0 ) {

			int len;
			int r;

			if ( remaining > 1500 ) {
				len = 1500;
			} else {
				len = remaining;
			}

			r = fread(buf, 1, len, f2 );

			if ( r < len) {
				printf("Error while reading\n");
				fclose(f2);
				return -1;
			}

			if ( send(fd, buf, r, 0) < 0 ) {
				printf("Problem while sending data to remote peer\n");
				fclose(f2);
				return -1;
			}

			remaining -= r;
		}

		fclose(f2);

	} else {
		printf("Cannot support paths\n");
	}

	return 0;
}

int process_client_get(context_t *ctx, int fd, char *request) {

	char *tmp = strtok(request, " ");
	char type[strlen(tmp)];
	strcpy(type,tmp);

	tmp = strtok(NULL, " ");
	if ( tmp == NULL) return -1;
	char file_name[strlen(tmp)];
	strcpy(file_name, tmp);

	tmp = strtok(NULL, " ");
	if ( tmp == NULL) return -1;
	long start_pos = atol(tmp);

	tmp = strtok(NULL, " ");
	if ( tmp == NULL) return -1;
	long bytes = atol(tmp);

	if (strcmp(type, "file") == 0) {

		if ( strcmp(file_name, "files.xml.bz2") == 0) {
			return send_files_list(ctx, fd);
		} else {
			return send_file(ctx, fd, file_name, start_pos, bytes);
		}

	} else if ( strcmp(type, "tthl") == 0) {
		return send_tth_list(ctx, fd, file_name, start_pos, bytes);
	}

	return -1;

}

int handle_peer( context_t *ctx, peer_t *peer, int port, char* token) {

	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if ( fd < 0 ) {
		return -1;
	}

	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr = peer->addr4;

	printf("Connecting to %s:%d\n", peer->sid, port);

	int ret = connect(fd, (struct sockaddr *) &addr, sizeof(addr));

	if ( ret < 0) {
		perror("Failed to connect");
		return -1;
	}

	printf("Connected to %s\n", peer->sid);

	/* send SUP message */

	if ( send_message_to_client(fd, "CSUP ADBASE ADTIGR\n") < 0) {
		return -1;
	}

	char message[MAX_STR_LEN];

	/* receive SUP message */

	if (read_message_from_client(fd, message, MAX_STR_LEN) < 0) {
		return -1;
	}

	if ( strncmp(message, "CSUP", 4) != 0) {
		return -1;
	}

	/* receive INF message */

	if (read_message_from_client(fd, message, MAX_STR_LEN) < 0) {
		return -1;
	}

	if ( strncmp(message, "CINF", 4) != 0) {
		return -1;
	}

	char *tmp = strtok(message + 5, " ");

	while (tmp != NULL) {
		if (strncmp(tmp, "ID", 2) == 0) {
			if ( strcmp(tmp + 2, peer->cid) != 0) {
				printf("We connected to the wrong peer '%s' vs '%s'\n", tmp+2, peer->cid);
			}
		}

		tmp = strtok(NULL, " ");
	}

	sprintf(message, "CINF TO%s ID%s\n", token, ctx->cid);

	send_message_to_client(fd, message);


	while ( 1) {

		/* get the request */

		if (read_message_from_client(fd, message, MAX_STR_LEN) < 0) {
			return -1;
		}

		if ( strncmp(message, "CGET ", 5) != 0) {
			return -1;
		}

		/* serve request */

		process_client_get(ctx, fd, message + 5);

	}

	return 0;

}

int connect_to_peer(context_t *ctx, char *sid, char* token, int port) {

	peer_t *peer = ctx->first_peer;

	while ( peer != NULL ) {
		if ( strcmp(peer->sid, sid) == 0) {
			break;
		}
		peer = peer->next;
	}

	if ( peer == NULL) {
		printf("Received connection request from inexistent peer\n");
		return -1;
	}

	pid_t pid = fork();

	if ( pid < 0 ) {
		printf("Can't fork\n");
		return -1;
	} else if ( pid == 0 ){
		// parent
		return 0;
	} else {
		handle_peer(ctx, peer, port, token);
		exit(1);
	}

	// eclipse is not smart enough
	return 0;
}

int process_d_message(context_t* ctx, char *message) {

	printf("Received D message %s\n", message);

	char *tmp = strtok(message, " ");
	if ( strlen(tmp) != 3) return -1;
	char command[4];
	strcpy(command, tmp);

	tmp = strtok(NULL, " ");
	if (strlen(tmp) != 4) return -1;
	char source_sid[5];
	strcpy(source_sid, tmp);

	// skip my sid
	tmp = strtok(NULL, " ");

	if ( strncmp(command, "CTM", 3) == 0) {

		tmp = strtok(NULL, " ");

		if ( strcmp(tmp, "ADC/1.0") != 0) {

			return -1;
		}

		tmp = strtok(NULL, " ");

		if (tmp == NULL) {
			return -1;
		}

		int port = atol(tmp);

		tmp = strtok(NULL, " ");

		if ( tmp == NULL) {
			return -1;
		}

		char token[strlen(tmp)];
		strcpy(token, tmp);

		connect_to_peer(ctx, source_sid, token, port);

	}

	return 0;
}

enum { SEARCH_AN, SEARCH_NO, SEARCH_EX, SEARCH_TR };

typedef struct _search_criteria_t {
	char *value;
	int type;
	struct _search_criteria_t* next;
} search_criteria_t;

char* stristr(char *string1, char* string2) {

	char string1u[strlen(string1) + 1];
	char string2u[strlen(string2) + 1];

	int i;

	for (i = 0 ; i< strlen(string1) ; i++) {
		string1u[i] = toupper(string1[i]);
	}
	string1u[i] = 0;

	for (i = 0 ; i< strlen(string2) ; i++) {
			string2u[i] = toupper(string2[i]);
	}
	string2u[i] = 0;

	return strstr(string1u, string2u);

}

int stricmp(char *string1, char* string2) {

	char string1u[strlen(string1) + 1];
	char string2u[strlen(string2) + 1];

	int i;

	for (i = 0 ; i< strlen(string1) ; i++) {
		string1u[i] = toupper(string1[i]);
	}
	string1u[i] = 0;

	for (i = 0 ; i< strlen(string2) ; i++) {
			string2u[i] = toupper(string2[i]);
	}
	string2u[i] = 0;

	return strcmp(string1u, string2u);

}

void find_results_in_dir(context_t *ctx, dir_t *dir, search_criteria_t* first_criteria, char* token, char* dest) {

	char *format = "DRES %s %s SI%ld SL1 FN%s TO%s TR%s\n";

	file_t *f = dir->first_file;

	int offset = strlen(ctx->root_path);

	while ( f != NULL ) {

		char *virtual_path = f->fullpath + offset;

		search_criteria_t *next_criteria = first_criteria;

		int matches = 1;
		int extension_match = 0;
		int extension_present = 0;

		char *extension = NULL;

		while ( next_criteria != NULL && matches == 1) {

			switch (next_criteria->type) {
			case SEARCH_AN:

				if ( stristr(f->name, next_criteria->value) == NULL) {
					matches = 0;
				}

				break;

			case SEARCH_EX:

				if ( extension == NULL) {
					extension = rindex(virtual_path, '.');
					if ( extension == NULL) {
						matches = 0;
						break;
					}
					extension++;
					extension_present = 1;
				}

				if ( stricmp(extension, next_criteria->value) == 0) {
					extension_match = 1;
				}

				break;
			case SEARCH_NO:

				if ( stristr(f->name, next_criteria->value) != NULL) {
					matches = 0;
				}

				break;
			case SEARCH_TR:

				if ( memcmp(f->root_tth, next_criteria->value, HASH_LEN) != 0) {
					matches = 0;
				}

				break;
			}

			next_criteria = next_criteria->next;

		}


		if ( matches && ( !extension_present || extension_match)) {

				char *virtual_path_escaped = escape_adc(virtual_path);

				char result[strlen(format) + SID_LEN + SID_LEN + CHARS_FOR_LONG + strlen(virtual_path_escaped) + strlen(token) + HASH_LEN_B32 + 1];

				sprintf(result, format, ctx->sid, dest, f->size, virtual_path_escaped, token, b32_hash(f->root_tth));

				send_message(ctx, result);

				free(virtual_path_escaped);

		}

		f = f->next;

	}

	dir_t *subdir = dir->first_subdir;

	while(subdir != NULL) {

		find_results_in_dir(ctx, subdir, first_criteria, token, dest);

		subdir = subdir->next;

	}



}

int process_sch_command(context_t* ctx, char *sid, char* command_args) {

	search_criteria_t *first_criteria = NULL;
	search_criteria_t *last_criteria = NULL;

	char *to = NULL;

	char *next_token = strtok(command_args, " ");

	while (next_token != NULL) {

		int token_len = strlen(next_token);

		if (strncmp(next_token, "AN", 2) == 0 ||
			strncmp(next_token, "NO", 2) == 0 ||
			strncmp(next_token, "EX", 2) == 0 ||
			strncmp(next_token, "TR", 2) == 0 )  {

			search_criteria_t *next_criteria = (search_criteria_t *) malloc( sizeof(search_criteria_t));

			if ( strncmp(next_token, "TR", 2) == 0 ) {
				next_criteria->value = (char *) malloc(HASH_LEN);
				decode_hash(next_token + 2, next_criteria->value);
			} else {
				next_criteria->value = (char *) malloc(strlen(next_token) - 2 + 1);
				strcpy(next_criteria->value, next_token + 2);
			}

			if (strncmp(next_token, "AN", 2) == 0 ) {
				next_criteria->type = SEARCH_AN;
			} else if (strncmp(next_token, "NO", 2) == 0 ) {
				next_criteria->type = SEARCH_NO;
			} else if (strncmp(next_token, "EX", 2) == 0 ) {
				next_criteria->type = SEARCH_EX;
			} else if (strncmp(next_token, "TR", 2) == 0 ) {
				next_criteria->type = SEARCH_TR;
			}

			next_criteria->next = NULL;

			if ( first_criteria == NULL ) {
				first_criteria = next_criteria;
			} else {
				last_criteria->next = next_criteria;
			}

			last_criteria = next_criteria;

		} else if ( strncmp(next_token, "TO", 2) == 0) {
			to = (char *) malloc(token_len - 1);
			strcpy(to, next_token + 2);
		}

		next_token = strtok(NULL,  " ");
	}

	if ( first_criteria != NULL && to != NULL) {
		find_results_in_dir(ctx, ctx->root_dir, first_criteria, to, sid);
	}

	while (first_criteria != NULL) {
		search_criteria_t *s = first_criteria;
		first_criteria = first_criteria->next;
		free(s);
	}

	if ( to != NULL ) free(to) ;

	return 0;
}

int process_inf_command(context_t* ctx, char* sid, char *message_args) {

	// skip if this is me
	if ( strcmp(sid, ctx->sid) == 0) return 0;

	char *nick = NULL;
	struct in_addr addr;
	int addrFound = 0;
	char cid[HASH_LEN_B32];
	int cidFound = 0;

	char *next = strtok(message_args, " ");

	addr.s_addr = 0;
	memset(cid, 0 , HASH_LEN_B32);

	while ( next != NULL) {
		if ( strncmp(next, "ID", 2) == 0) {
			if (strlen(next + 2) != HASH_LEN_B32 - 1) {
				continue;
			}
			memcpy(cid, next + 2, HASH_LEN_B32);
			cidFound = 1;
		} else if ( strncmp(next, "NI", 2) == 0) {
			nick = (char *) malloc(strlen(next+2) + 1);
			strcpy(nick, next+2);
		} else if ( strncmp(next, "I4", 2) == 0) {

			if ( inet_aton(next+2, &addr) == 0 ) {
				printf("Error parsing address\n");
			}
			addrFound = 1;

		}

		next = strtok(NULL,  " ");
	}

	peer_t *peer = find_peer(ctx, sid);

	if ( peer == NULL ) {

		peer = create_peer(sid, cid, nick, &addr);
		peer->next = ctx->first_peer;
		ctx->first_peer = peer;

		printf("Peer %s (%s) on ip %s available\n", peer->nick, peer->sid, inet_ntoa(addr));

	} else {

		if (nick != NULL) {
			free(peer->nick);
			peer->nick = (char *) malloc(strlen(nick) + 1);
			strcpy(peer->nick, nick);
			printf("Peer %s (%s) changed name\n", peer->nick, peer->sid);
		}

		if (addrFound) {
			peer->addr4 = addr;
			printf("Peer %s (%s) changed IP to %s\n", peer->nick, peer->sid, inet_ntoa(addr));
		}

		if (cidFound) {
			memcpy(peer->cid, cid, HASH_LEN_B32);
			printf("Peer %s (%s) changed CID\n", peer->nick, peer->sid);
		}


	}

	if (nick != NULL) free(nick);

	return 0;
}

int process_b_message(context_t* ctx, char *message) {

	/* this message is not valid */
	if ( strlen(message) < 5 ) {
		return -1;
	}

	printf("%s\n", message);

	char command[4];
	memcpy(command, message, 3);
	command[3] = 0;

	char sid[SID_LEN];
	memcpy(sid, message + 4, SID_LEN - 1);
	sid[SID_LEN - 1] = 0;

	char *message_args = message + 4 + SID_LEN;

	if ( strcmp(command, "SCH") == 0) {

		return process_sch_command(ctx, sid, message_args);

	} else if ( strcmp(command, "INF") == 0 ) {

		return process_inf_command(ctx, sid, message_args);

	} else {
		printf("Received B message %s\n", message);
	}

	return 0;
}

int process_f_message(context_t* ctx, char *message) {

	/* this message is not valid */
	if ( strlen(message) < 5 ) {
		return -1;
	}

	printf("%s\n", message);

	char command[4];
	memcpy(command, message, 3);
	command[3] = 0;

	char sid[SID_LEN];
	memcpy(sid, message + 4, SID_LEN - 1);
	sid[SID_LEN - 1] = 0;

	char *message_args = message + 4 + SID_LEN;

	while (message_args[0] == '-' ||
			message_args[0] == '+') {

		message_args = index(message_args, ' ') + 1;

	}

	if ( strcmp(command, "SCH") == 0) {

		return process_sch_command(ctx, sid, message_args);

	} else {
		printf("Received F message %s\n", message);
	}

	return 0;
}

int process_i_message(context_t* ctx, char *message) {

	/* this message is not valid */
	if ( strlen(message) < 4 ) {
		return -1;
	}

	if ( strncmp(message, "STA", 3) == 0) {
		int code;
		char desc[MAX_STR_LEN];

		if (sscanf(message, "STA %d %s\n", &code, desc) < 2) {
			return -1;
		}
			
		char *desc_d = remove_adc_escapes(desc);

		printf("Hub says %d with message %s\n", code, desc_d);

		free(desc_d);

	} else if ( strncmp(message, "SUP", 3) == 0) {

		char *pos = strtok(message, " ");

		while ( (pos = strtok(NULL, " ")) != NULL ) {

			int enable = 0;
	
			if ( strncmp(pos, "AD", 2) == 0) {
				enable = 1;					
			} else if ( strncmp(pos, "RM", 2) == 0) {
				enable = 0;
			} else {
				printf("Invalid SUP message\n");
				return -1;
			}

			/* skip AD/RM */
			pos = pos + 2;

			if ( strcmp(pos, "TIGR") == 0 ) {
				ctx->features.tigr = enable;
			} else if ( strcmp(pos, "BASE") == 0 ) {
				ctx->features.base = enable;
			} else if ( strcmp(pos, "PING") == 0 ) {
				ctx->features.ping = enable;
			} else {
				printf("Unsupported feature %s received\n", pos);
			}
					
		}
	} else if ( strncmp(message, "SID", 3) == 0) {

		if ( ctx->state != STATE_PROTOCOL) return -1;

		if ( strlen(message) != 8 ) {
			printf("Invalid SID received\n");
		}

		if ( sscanf(message, "SID %s", ctx->sid) < 1) {
			return -1;
		}

		char response[MAX_STR_LEN];
		sprintf(response, "BINF %s VE0.0.1 NI%s DEminiadcs\\sclient PD%s ID%s SUADCS\n", ctx->sid, ctx->nickname, ctx->pid, ctx->cid);

		send_message(ctx, response);


	} else if ( strncmp(message, "MSG", 3) == 0) {

		char *pos = strtok(message, " ");

		while ( ( pos = strtok(NULL, " ")) != NULL )  {
			
			if ( strncmp(pos, "PM", 2) == 0) {
				
			} else if ( strncmp(pos, "ME", 2) == 0 ) {
			
			} else {
				char desc[MAX_STR_LEN];

				if (sscanf(pos, "%s\n", desc) < 1) {
					return -1;
				}
					
				char *desc_d = remove_adc_escapes(desc);
				printf("Hub> %s\n", desc_d);
				free(desc_d);
			}

		}

	} else if ( strncmp(message, "GPA", 3) == 0) {

		if ( strlen(message) < 5) {
			return -1;
		}

		char *b32_gpa = message + 4;


		char token[HASH_LEN_B32];

		create_password(b32_gpa, ctx->password, token);

		char response[MAX_STR_LEN];

		sprintf(response, "HPAS %s\n", token);

		send_message(ctx, response);

	} else if ( strncmp(message, "QUI", 3) == 0) {

		strtok(message, " ");

		char *sid = strtok(NULL, " ");

		if ( strcmp(sid, ctx->sid) == 0) {
			printf("Server is kicking me\n");
			return -1;
		}

		peer_t *peer = ctx->first_peer;

		if ( strcmp(peer->sid, sid) == 0) {
			ctx->first_peer = peer->next;
		}

		while ( peer->next != NULL) {
			if ( strcmp(peer->next->sid, sid) == 0) {
				peer->next = peer->next->next;
				break;
			}

			peer = peer->next;
		}

		printf("Peer %s disconnected\n", sid);

	} else if ( strncmp(message, "INF", 3) == 0) {

		strtok(message, " ");

		char *nick = NULL;
		char *desc = NULL;

		char *tmp;

		while (  ( tmp = strtok(NULL, " ")) != NULL) {

			if ( strncmp(tmp, "NI", 2) == 0) {
				nick = remove_adc_escapes(tmp + 2);
			} else if ( strncmp(tmp, "DE", 2) == 0) {
				desc = remove_adc_escapes(tmp + 2);
			}

		}


		if ( nick != NULL && desc != NULL) {
			printf("Hub %s - %s\n", nick, desc);
		}

		if (  nick != NULL) free(nick);
		if (  desc != NULL) free(desc);

	} else {
		printf("Received I message: %s\n", message);
	}

	return 0;

}

int process_message_from_hub( context_t *ctx ) {


	char message[MAX_STR_LEN];

	int ret = read_message(ctx, message, MAX_STR_LEN);
	
	if ( ret < 0 ) {
		return -1;
	}

	/* delete the new line at the end of the message*/
	message[strlen(message) - 1] = 0;

	/* zero length message */
	if ( strlen(message) == 0 ) {
		return 0;
	}

	/* this message is not valid */
	if ( strlen(message) < 4 ) {
		return -1;
	}

	char type = message[0];


	printf("Received: %s\n", message);

	/* check the type of message */
	switch (type) {
		case 'I':
			process_i_message(ctx, message + 1);
			break;
		case 'B':
			process_b_message(ctx, message + 1);
			break;
		case 'D':
			process_d_message(ctx, message + 1);
			break;
		case 'F':
			process_f_message(ctx, message + 1);
			break;
		default:
			printf("Received: %s\n", message);
			break;
	}
	
	return 0;

}


int send_message( context_t* ctx, char* message ) {

	int ret;

	ret = gnutls_record_send (ctx->session, message, strlen (message));

	if ( ret < 0 ) {
                fprintf (stderr, "Error: %s\n", gnutls_strerror (ret));
                return -1;
        } else if ( ret == 0 ) {
                printf ("Peer has closed the TLS connection\n");
                return -1;
        }

	return 0;
}

int main (int argc, char** argv ) {

	if ( argc != 7) {

		printf("usage: miniadc hub port nick password root index\n");
		exit(1);
	}

	char *hub_address = argv[1];
	int hub_port = atoi(argv[2]);
	if ( hub_port == 0) {
		printf("Invalid hub port\n");
		exit(1);
	}
	char *nickname = argv[3];
	char *password = argv[4];
	char *root = argv[5];
	char *index = argv[6];

	context_t ctx;

	printf("Indexing files...\n");

	ctx.root_path = root;
	ctx.root_dir = index_directory(root, index);

	if ( ctx.root_dir == NULL) {
		printf("Unable to index shared directory\n");
		exit(1);
	}

	printf("Connecting to hub...\n");

	const char *err;
	int sd, ret;

	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;

	gnutls_global_init ();

	gnutls_certificate_allocate_credentials (&xcred);
	gnutls_certificate_set_verify_function (xcred, _verify_certificate_callback);

	gnutls_init (&session, GNUTLS_CLIENT);

	ret = gnutls_priority_set_direct (session, "NORMAL", &err);
	if (ret < 0) {
		if (ret == GNUTLS_E_INVALID_REQUEST) {
			fprintf (stderr, "Syntax error at: %s\n", err);
		}
		exit (1);
	}
	
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

	sd = socket(AF_INET, SOCK_STREAM, 0);

	struct hostent* remote = gethostbyname(hub_address);

	if ( remote == NULL) {
		perror("Unable to resolve remote address");
		exit(1);
	}

	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(hub_port);
	addr.sin_addr.s_addr = ((struct in_addr*) remote->h_addr_list[0])->s_addr;

	if ( connect(sd, (struct sockaddr*) &addr, sizeof(addr)) < 0 ) {
		perror("Unable to connect to remote host");
		exit(1);
	}

	gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) (intptr_t) sd);

	do {
		ret = gnutls_handshake (session);
	} while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if ( ret < 0 ) {
		fprintf (stderr, "TLS Handshake failed\n");
		gnutls_perror(ret);
	} else {
		printf("Handshake completed\n");
	}

	ctx.sd = sd;
	ctx.session = session;
	ctx.state = STATE_PROTOCOL;

	create_pid(ctx.pid);
	create_cid(ctx.pid, ctx.cid);

	ctx.nickname = nickname;
	ctx.password = password;

	send_message(&ctx, "HSUP ADBASE ADTIGR\n");

	while ( 1 ) {
		ret = process_message_from_hub(&ctx);

		if (ret < 0) {
			printf("Disconnected\n");
			exit(1);
		}
	}


}


static int _verify_certificate_callback (gnutls_session_t session) {
	return 0;
}
