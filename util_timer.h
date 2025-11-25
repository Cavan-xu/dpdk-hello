#ifndef NG_UTIL_TIMER_H
#define NG_UTIL_TIMER_H

#include <rte_timer.h>

void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg);

#endif