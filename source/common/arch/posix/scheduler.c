#include "queue.h"
#include "common.h"
#include <poll.h>

#include <pthread.h>

typedef struct _WaitableEntry
{
	HANDLE                waitable;
	LPVOID                context;
	WaitableNotifyRoutine routine;
	LIST_ENTRY(_WaitableEntry) link;
} WaitableEntry;

int nentries = 0;
int ntableentries = 0;
struct pollfd *polltable;
LIST_HEAD(_WaitableEntryHead, _WaitableEntry) WEHead;

THREAD *scheduler_thread;

/*
 * If there are no waitables in the queue, we wait
 * for a conditional broadcast to start it.
 */

pthread_mutex_t scheduler_mutex;
pthread_cond_t scheduler_cond;

DWORD scheduler_run(THREAD *thread);
     
DWORD scheduler_destroy( VOID )
{
	WaitableEntry *current, *tmp;

	dprintf("Shutdown of scheduler requested");

	if(scheduler_thread)
	{
		dprintf("sigterm'ing thread");
		thread_sigterm(scheduler_thread);

		// wake up the thread if needed
		pthread_cond_signal(&scheduler_cond);

		// can delay execution up to 2 sec give or take
		thread_join(scheduler_thread);

		// free up memory
		thread_destroy(scheduler_thread);
		scheduler_thread = NULL;

		dprintf("thread joined .. going for polltable");

		if(polltable)
		{
			free(polltable);
			polltable = NULL;
			nentries = ntableentries = 0;
		}

		dprintf("Now for the fun part, iterating through list and removing items");

		LIST_FOREACH_SAFE(current, &WEHead, link, tmp)
		{
			// can't call close function due to no remote struct
			// will segfault if we try
			// XXX could steal from scheduler_thread->parameter1 ?

			dprintf("current: %08x, current->routine: %08x", current, current->routine);

			LIST_REMOVE(current, link);
			close(current->waitable);
			free(current->context);
			free(current);
		}

		dprintf("All done. Leaving");

	}
	return ERROR_SUCCESS;
}

DWORD scheduler_initialize( Remote * remote )
{
	if(scheduler_thread) {
		dprintf("Hmmm. scheduler_initialize() called twice?");
		return ERROR_SUCCESS;
	}

	pthread_mutex_init(&scheduler_mutex, NULL);
	pthread_cond_init(&scheduler_cond, NULL);

	scheduler_thread = thread_create(scheduler_run, remote, NULL, NULL);
	if(! scheduler_thread) {
		return ENOMEM;
	}

	thread_run(scheduler_thread);

	dprintf("Initialized scheduler thread and started it running");

	return ERROR_SUCCESS;
}

/*
 * Insert a waitable object for checking and processing
 */
DWORD
scheduler_insert_waitable(HANDLE waitable, LPVOID context,
    WaitableNotifyRoutine routine)
{
	DWORD retcode = ERROR_SUCCESS;

	WaitableEntry *current;
	struct pollfd *polltableprev;

	pthread_mutex_lock(&scheduler_mutex);

	//dprintf("Handle: %d, context: 0x%08x, routine: 0x%08x. nentries = %d, polltable = 0x%08x",
	//	waitable, context, routine, nentries, polltable);

	do {
		if ((current = malloc(sizeof(WaitableEntry))) == NULL) {
			retcode = ENOMEM;
			break;
		}

		nentries++;

		if (nentries > ntableentries) {
			polltableprev = polltable;

			// We do *2 because reallocating every scheduler_insert_waitable
			// is slower than need be.

			polltable = malloc((nentries*2)*sizeof(struct pollfd));

			if (polltable == NULL) {
				nentries--;
				polltable = polltableprev;
				free(current);

				retcode = ENOMEM;
				break;
			}

			if (polltableprev != NULL)
				free(polltableprev);

			ntableentries = (nentries*2);
		}
		current->waitable = waitable;
		current->context = context;
		current->routine = routine;

		LIST_INSERT_HEAD(&WEHead, current, link);


	} while(0);


	dprintf("WEHead: %08x, Now nentries = %d, and polltable = 0x%08x. LIST_EMPTY: %d", &WEHead, nentries, polltable, LIST_EMPTY(&WEHead));
	/*
	LIST_FOREACH(current, &WEHead, link)
		dprintf("current->waitable: %d, current->context: %08x, current->routine: %08x",
			current->waitable, current->context, current->routine);
	*/

	pthread_mutex_unlock(&scheduler_mutex);

	// wake up scheduler if needed.
	pthread_cond_signal(&scheduler_cond);

	return retcode;
}

/*
 * Remove a waitable object
 */
DWORD
scheduler_remove_waitable(HANDLE waitable)
{
	DWORD retcode = ERROR_SUCCESS;
	WaitableEntry *current;

	dprintf("Handle: %d", waitable);

	pthread_mutex_lock(&scheduler_mutex);

	do {
		LIST_FOREACH(current, &WEHead, link)
		    if (current->waitable == waitable)
			    break;

		if (current == NULL) {
			retcode = ENOENT;
			break;
		}

		LIST_REMOVE(current, link);
		free(current);
		nentries--;
	} while(0);

	pthread_mutex_unlock(&scheduler_mutex);

	return retcode;
}

/*
 * Runs the scheduler, checking waitable objects for data
 */
DWORD
scheduler_run(THREAD *thread)
{
	Remote *remote;
	remote = (Remote *) thread->parameter1;
	WaitableEntry *current, *tmp;
	int ret, i, found, idx;
	int timeout;

	timeout = 1000;

	// see if we can modify this code to use waitable as the index into polltable
	// and waitable events. saves time looking up in exchange for more memory use.

	pthread_mutex_lock(&scheduler_mutex);

	dprintf("Beginning loop");

	while( event_poll(thread->sigterm, 0) == FALSE )
	{
		// scheduler_mutex is held upon entry and execution of the loop

		idx = 0;

		while(event_poll(thread->sigterm, 0) == FALSE && (LIST_EMPTY(&WEHead) || polltable == NULL)) {
			// XXX I'd prefer to use pthread_cond_timedwait, but it's broken in bionic and just
			// chews cpu

			//dprintf(" Waiting for conditional (%08x). %d vs %d",
			//	&scheduler_cond, LIST_EMPTY(&WEHead), polltable == NULL);

			pthread_cond_wait(&scheduler_cond, &scheduler_mutex);

			// pthread_cond_wait still chews CPU in some cases, usleep to yield
			// processor so we don't just spin.
			usleep(1000);
		}

		LIST_FOREACH(current, &WEHead, link) {
			dprintf("current->waitable: %d, current->context: %08x, current->routine: %08x",
				current->waitable, current->context, current->routine);
			polltable[idx].fd = current->waitable;
			polltable[idx].events = POLLRDNORM;
			polltable[idx].revents = 0;
			idx++;
		}

		dprintf("Created a polltable of %d", idx);

		pthread_mutex_unlock(&scheduler_mutex);

		ret = poll(polltable, idx, timeout);

		pthread_mutex_lock(&scheduler_mutex);

		if(ret == 0) continue;
		if(ret == -1) {
			if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				continue;
			}
			dprintf("poll() failed, errno: %d (%s). Sleeping 1 second and retrying", errno, strerror(errno));
			sleep(1);
			continue;
		}

		for (found = i = 0; i < idx && found < ret; i++)
		{
			if (polltable[i].revents)
			{
				LIST_FOREACH(current, &WEHead, link)
				    if (current->waitable == polltable[i].fd)
					    break;

				if(current)
				{
					ret = current->routine(remote, current->context);
					if(ret != ERROR_SUCCESS)
					{
						// could call close due to remote, but it would deadlock
						// if it calls remove waitable
						// could make a separate list to handle when we are not locking
						// unlink and let rest deal with it ?

						dprintf("current->routine (%08x / %08x) returned an error message. destroying", current->routine, current->context);

						LIST_REMOVE(current, link);
						close(current->waitable);
						channel_close((Channel *)current->context, remote, NULL, 0, NULL);
						free(current);

						nentries--;

					}
				}
			}
		}
	}

	dprintf("Ending loop");

	pthread_mutex_unlock(&scheduler_mutex);
}


