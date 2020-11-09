/*
 * librpma_gpspm: IO engine that uses PMDK librpma to read and write data,
 *                it is a variant of librpma engine in GPSPM mode
 *
 * Copyright 2020, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "../fio.h"
#include "../hash.h"
#include "../optgroup.h"

#include <libpmem.h>
#include <librpma.h>

#define rpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

/* client's and server's common */

/* XXX */

/* client side implementation */

struct client_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *hostname;
	char *port;
};

static struct fio_option fio_client_options[] = {
	{
		.name	= "hostname",
		.lname	= "rpma_client hostname",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct client_options, hostname),
		.help	= "IP address the server is listening on",
		.def    = "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "port",
		.lname	= "rpma_client port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct client_options, port),
		.help	= "port the server is listening on",
		.def    = "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= NULL,
	},
};

struct client_data {
	/* XXX */
};

static int client_init(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static int client_post_init(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static void client_cleanup(struct thread_data *td)
{
	/* XXX */
}

static int client_get_file_size(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static int client_open_file(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static int client_close_file(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static enum fio_q_status client_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	/* XXX */
	return FIO_Q_BUSY;
}

static int client_commit(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static int client_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	/* XXX */
	return 0;
}

static struct io_u *client_event(struct thread_data *td, int event)
{
	/* XXX */
	return 0;
}

static char *client_errdetails(struct io_u *io_u)
{
	/* XXX */
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_gpspm_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.get_file_size		= client_get_file_size,
	.open_file		= client_open_file,
	.queue			= client_queue,
	.commit			= client_commit,
	.getevents		= client_getevents,
	.event			= client_event,
	.errdetails		= client_errdetails,
	.close_file		= client_close_file,
	.cleanup		= client_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= fio_client_options,
	.option_struct_size	= sizeof(struct client_options),
};

/* server side implementation */

struct server_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *bindname;
	char *port;
	unsigned int num_conns;
};

static struct fio_option fio_server_options[] = {
	{
		.name	= "bindname",
		.lname	= "rpma_server bindname",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct server_options, bindname),
		.help	= "IP address to listen on for incoming connections",
		.def    = "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "port",
		.lname	= "rpma_server port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct server_options, port),
		.help	= "port to listen on for incoming connections",
		.def    = "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "num_conns",
		.lname	= "Number of connections",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct server_options, num_conns),
		.help	= "Number of connections to server",
		.minval = 1,
		.def	= "1",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= NULL,
	},
};

struct server_data {
	struct rpma_peer *peer;
	struct rpma_ep *ep;

	/* size of the mapped persistent memory */
	size_t size_pmem;
};

static int server_init(struct thread_data *td)
{
	struct server_options *o = td->eo;
	struct server_data *sd;
	struct ibv_context *dev = NULL;
	char *port;
	int ret = 1;

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_DEBUG);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_DEBUG);

	/* set value of port specific for the current thread */
	ret = asprintf(&port, "%i", atoi(o->port) + td->thread_number - 1);
	if (ret) {
		log_err("asprintf() failed");
		return 1;
	}

	/* allocate server's data */
	sd = calloc(1, sizeof(struct server_data));
	if (sd == NULL) {
		td_verror(td, errno, "calloc");
		return 1;
	}

	if (td->o.mem_type == MEM_MMAP) {
		/*
		 * Zero mem_type if mem_type == MEM_MMAP,
		 * because we want server_iomem_alloc() to be called
		 * in this case, but custom iomem hooks are called
		 * only if mem_type has never been set before.
		 */
		td->o.mem_type = 0;
		/* XXX HACK - make the mem_type option unset */
		td->o.set_options[1] &= ~(uint64_t)1;
	} else {
		/*
		 * Reset iomem hooks if mem_type != MEM_MMAP,
		 * because server_iomem_alloc() should be called
		 * only if td->o.mem_type == MEM_MMAP.
		 */
		td->io_ops->iomem_alloc = NULL;
		td->io_ops->iomem_free = NULL;
	}

	/* obtain an IBV context for a remote IP address */
	ret = rpma_utils_get_ibv_context(o->bindname,
				RPMA_UTIL_IBV_CONTEXT_LOCAL,
				&dev);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		goto err_free_sd;
	}

	/* create a new peer object */
	ret = rpma_peer_new(dev, &sd->peer);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_sd;
	}

	/* start a listening endpoint at addr:port */
	ret = rpma_ep_listen(sd->peer, o->bindname, port, &sd->ep);
	free(port);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_ep_listen");
		goto err_peer_delete;
	}

	td->io_ops_data = sd;

	/*
	 * Each connection needs its own workspace which will be allocated as
	 * io_u. So the number of io_us has to be equal to the number of
	 * connections the server will handle and...
	 */
	td->o.iodepth = o->num_conns;

	/*
	 * ... a single io_u size has to be equal to the assumed workspace size.
	 */
	td->o.max_bs[DDIR_READ] = td->o.size;

	return 0;

err_peer_delete:
	(void) rpma_peer_delete(&sd->peer);

err_free_sd:
	free(sd);

	return ret;
}

static int server_post_init(struct thread_data *td)
{
	/*
	 * - rpma_recv()
	 */
	return 0;
}

static void server_cleanup(struct thread_data *td)
{
	/*
	 * - rpma_ep_shutdown
	 * - rpma_peer_delete
	 */
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	/*
	 * - rpma_mr_reg(PMem)
	 * - rpma_mr_reg(messaging buffer from DRAM)
	 * - rpma_mr_get_descriptor_size
	 * - verify size of the memory region's descriptor
	 * - rpma_mr_get_descriptor
	 */
	return 0;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	/*
	 * - rpma_mr_dereg(PMem)
	 * - rpma_mr_dereg(messaging buffer from DRAM)
	 * - FILE_SET_ENG_DATA(f, NULL);
	 */
	return 0;
}

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	/*
	 * - rpma_conn_completion_wait()
	 * - rpma_conn_completion_get()
	 * - pmem_persist(f, NULL);
	 */
	return FIO_Q_BUSY;
}

/*
 * server_iomem_alloc -- allocates memory from PMem using pmem_map_file()
 * (PMem version of mmap()) from the PMDK's libpmem library
 */
static int server_iomem_alloc(struct thread_data *td, size_t size)
{
	struct server_data *sd =  td->io_ops_data;
	size_t size_pmem = 0;
	void *mem = NULL;
	int is_pmem = 0;

	if (!td->o.mmapfile) {
		log_err("fio: mmapfile is not set\n");
		return 1;
	}

	/* map the file */
	mem = pmem_map_file(td->o.mmapfile, 0 /* len */, 0 /* flags */,
			0 /* mode */, &size_pmem, &is_pmem);
	if (mem == NULL) {
		log_err("fio: pmem_map_file(%s) failed\n", td->o.mmapfile);
		/* pmem_map_file() sets errno on failure */
		td_verror(td, errno, "pmem_map_file");
		return 1;
	}

	/* pmem is expected */
	if (!is_pmem) {
		log_err("fio: %s is not located in persistent memory\n", td->o.mmapfile);
		(void) pmem_unmap(mem, size_pmem);
		return 1;
	}

	/* check size of allocated persistent memory */
	if (size_pmem < size) {
		log_err("fio: failed to allocate enough amount of persistent memory (%zu < %zu)\n",
			size_pmem, size);
		(void) pmem_unmap(mem, size_pmem);
		return 1;
	}

	sd->size_pmem = size_pmem;
	td->orig_buffer = mem;

	dprint(FD_MEM, "server_iomem_alloc %llu %p\n",
		(unsigned long long) size, td->orig_buffer);

	return 0;
}

static void server_iomem_free(struct thread_data *td)
{
	struct server_data *sd = td->io_ops_data;

	if (td->orig_buffer == NULL || sd == NULL)
		return;

	(void) pmem_unmap(td->orig_buffer, sd->size_pmem);

	td->orig_buffer = NULL;
	td->orig_buffer_size = 0;
}

static int server_invalidate(struct thread_data *td, struct fio_file *file)
{
	/* NOP */
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_gpspm_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.post_init		= server_post_init,
	.open_file		= server_open_file,
	.close_file		= server_close_file,
	.queue			= server_queue,
	.invalidate		= server_invalidate,
	.cleanup		= server_cleanup,
	.iomem_alloc		= server_iomem_alloc,
	.iomem_free		= server_iomem_free,
	.flags			= FIO_SYNCIO | FIO_NOEXTEND | FIO_FAKEIO |
				  FIO_NOSTATS,
	.options		= fio_server_options,
	.option_struct_size	= sizeof(struct server_options),
};

/* register both engines */

static void fio_init fio_librpma_gpspm_register(void)
{
	register_ioengine(&ioengine_client);
	register_ioengine(&ioengine_server);
}

static void fio_exit fio_librpma_gpspm_unregister(void)
{
	unregister_ioengine(&ioengine_client);
	unregister_ioengine(&ioengine_server);
}
