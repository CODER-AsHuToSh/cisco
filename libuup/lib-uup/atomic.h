#ifndef ATOMIC_H
#define ATOMIC_H

#define ATOMIC_DEC_INT_NV(PTR) __sync_add_and_fetch((PTR), -1)
#define ATOMIC_INC_INT(PTR)    __sync_fetch_and_add((PTR),  1)

#endif
