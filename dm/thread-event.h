/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __THREAD_EVENT_H__
#define __THREAD_EVENT_H__

#ifdef _WIN32
typedef HANDLE thread_event;
#else
typedef struct thread_event {
    int set;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} thread_event;
#endif

static inline
int thread_event_init(thread_event *ev)
{
#ifdef _WIN32
    if (!(*ev = CreateEvent(NULL, FALSE, FALSE, NULL))) {
        Werr(1, "%s: CreateEvent failed", __FUNCTION__);
        return -1;
    }
#else
    ev->set = 0;
    pthread_mutex_init(&ev->mutex, NULL);
    pthread_cond_init(&ev->cond, NULL);
#endif
    return 0;
}

static inline
void thread_event_set(thread_event *ev)
{
#ifdef _WIN32
    SetEvent(*ev);
#else
    pthread_mutex_lock(&ev->mutex);
    ev->set = 1;
    pthread_mutex_unlock(&ev->mutex);
    pthread_cond_signal(&ev->cond);
#endif
}

static inline
void thread_event_wait(thread_event *ev)
{
#ifdef _WIN32
    WaitForSingleObject(*ev, INFINITE);
#else
    pthread_mutex_lock(&ev->mutex);
    while (!ev->set)
        pthread_cond_wait(&ev->cond, &ev->mutex);
    ev->set = 0;
    pthread_mutex_unlock(&ev->mutex);
#endif
}

static inline
void thread_event_close(thread_event *ev)
{
#ifdef _WIN32
    CloseHandle(*ev);
#else
    pthread_cond_destroy(&ev->cond);
    pthread_mutex_destroy(&ev->mutex);
#endif
}

#endif /* __THREAD_EVENT_H__ */
