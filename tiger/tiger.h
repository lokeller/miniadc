/*
 *
 * Tiger: A Fast New Hash Function
 * Ross Anderson and Eli Biham
 *
 * http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 *
 * Tiger has no usage restrictions nor patents. It can be used freely,
 * with the reference implementation, with other implementations or with
 * a modification to the reference implementation (as long as it still
 * implements Tiger). We only ask you to let us know about your
 * implementation and to cite the origin of Tiger and of the reference
 * implementation.
 *
 *
 */

#ifndef __TIGER_H__
#define __TIGER_H__

#include <stdint.h>

void tiger(uint64_t *str, uint64_t length, uint64_t res[3]);

#endif
