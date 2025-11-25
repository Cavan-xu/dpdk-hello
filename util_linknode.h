#ifndef NG_UTIL_LINKNODE_H
#define NG_UTIL_LINKNODE_H

#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)

#define LL_REMOVE(item, list) do {  \
    if (item->prev != NULL) item->prev->next = item->next;  \
    if (item->next != NULL) item->next->prev = item->prev;  \
    if (list == item) list = item->next;\
    item->next=item->prev = NULL;\
} while(0)

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

#endif