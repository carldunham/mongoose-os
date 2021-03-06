/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef __TI_COMPILER_VERSION__
#include <malloc.h>
#endif
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "inc/hw_types.h"
#include "inc/hw_memmap.h"

#include "driverlib/prcm.h"
#include "driverlib/rom.h"
#include "driverlib/rom_map.h"
#include "driverlib/wdt.h"

#include "common/platform.h"
#include "common/cs_dbg.h"

#include "simplelink.h"
#include "device.h"
#include "oslib/osi.h"
#include "FreeRTOS.h"
#include "semphr.h"

#include "fw/src/mgos_hal.h"

#include "fw/platforms/cc3200/src/config.h"
#include "fw/platforms/cc3200/src/cc3200_fs.h"

#include "common/umm_malloc/umm_malloc.h"

#ifdef __TI_COMPILER_VERSION__

size_t mgos_get_heap_size(void) {
  return UMM_MALLOC_CFG__HEAP_SIZE;
}

size_t mgos_get_free_heap_size(void) {
  return umm_free_heap_size();
}

size_t mgos_get_min_free_heap_size(void) {
  return umm_min_free_heap_size();
}

#else

/* Defined in linker script. */
extern unsigned long _heap;
extern unsigned long _eheap;

size_t mgos_get_heap_size(void) {
  return ((char *) &_eheap - (char *) &_heap);
}

size_t mgos_get_free_heap_size(void) {
  size_t avail = mgos_get_heap_size();
  struct mallinfo mi = mallinfo();
  avail -= mi.arena;    /* Claimed by allocator. */
  avail += mi.fordblks; /* Free in the area claimed by allocator. */
  return avail;
}

size_t mgos_get_min_free_heap_size(void) {
  /* Not supported */
  return 0;
}

#endif

size_t mgos_get_fs_memory_usage(void) {
  return 0; /* Not even sure if it's possible to tell. */
}

void mgos_wdt_feed(void) {
  MAP_WatchdogIntClear(WDT_BASE);
}

void mgos_wdt_set_timeout(int secs) {
  MAP_WatchdogUnlock(WDT_BASE);
  /* Reset is triggered after the timer reaches zero for the second time. */
  MAP_WatchdogReloadSet(WDT_BASE, secs * SYS_CLK / 2);
  MAP_WatchdogLock(WDT_BASE);
}

void mgos_wdt_enable(void) {
  MAP_WatchdogUnlock(WDT_BASE);
  MAP_WatchdogEnable(WDT_BASE);
  MAP_WatchdogLock(WDT_BASE);
}

void mgos_wdt_disable(void) {
  LOG(LL_ERROR, ("WDT cannot be disabled!"));
}

void mgos_system_restart(int exit_code) {
  (void) exit_code;
  if (exit_code != 100) {
    cc3200_fs_umount();
    sl_Stop(50 /* ms */);
  }
  /* Turns out to be not that easy. In particular, using *Reset functions is
   * not a good idea.
   * https://e2e.ti.com/support/wireless_connectivity/f/968/p/424736/1516404
   * Instead, the recommended way is to enter hibernation with immediate wakeup.
   */
  MAP_PRCMHibernateIntervalSet(328 /* 32KHz ticks, 100 ms */);
  MAP_PRCMHibernateWakeupSourceEnable(PRCM_HIB_SLOW_CLK_CTR);
  MAP_PRCMHibernateEnter();
}

void mgos_msleep(uint32_t msecs) {
  osi_Sleep(msecs);
}

void mgos_usleep(uint32_t usecs) {
  osi_Sleep(usecs / 1000 /* ms */);
}

uint32_t mgos_bitbang_n100_cal;
void (*mgos_nsleep100)(uint32_t n);
void cc3200_nsleep100(uint32_t n) {
  /* TODO(rojer) */
}

void mgos_ints_disable(void) {
  MAP_IntMasterDisable();
}

void mgos_ints_enable(void) {
  MAP_IntMasterEnable();
}

void mongoose_poll_cb(void *arg);

static bool s_mg_poll_scheduled;

void mongoose_schedule_poll(bool from_isr) {
  /* Prevent piling up of poll callbacks. */
  if (s_mg_poll_scheduled) return;
  s_mg_poll_scheduled = mgos_invoke_cb(mongoose_poll_cb, NULL, from_isr);
}

void mongoose_poll_cb(void *arg) {
  s_mg_poll_scheduled = false;
  (void) arg;
}

SemaphoreHandle_t s_mgos_mux = NULL;

void mgos_lock_init(void) {
  s_mgos_mux = xSemaphoreCreateRecursiveMutex();
}

void mgos_lock(void) {
  while (!xSemaphoreTakeRecursive(s_mgos_mux, 10)) {
  }
}

void mgos_unlock(void) {
  while (!xSemaphoreGiveRecursive(s_mgos_mux)) {
  }
}

int mgos_adc_read(int pin) {
  /* TODO(rojer): implement */
  (void) pin;
  return 0;
}
