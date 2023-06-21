/*
 * © 2021. Triad National Security, LLC. All rights reserved.
 *
 * This program was produced under U.S. Government contract
 * 89233218CNA000001 for Los Alamos National Laboratory (LANL), which
 * is operated by Triad National Security, LLC for the U.S.
 * Department of Energy/National Nuclear Security Administration. All
 * rights in the program are reserved by Triad National Security, LLC,
 * and the U.S. Department of Energy/National Nuclear Security
 * Administration. The Government is granted for itself and others
 * acting on its behalf a nonexclusive, paid-up, irrevocable worldwide
 * license in this material to reproduce, prepare derivative works,
 * distribute copies to the public, perform publicly and display
 * publicly, and to permit others to do so.
 *
 * ----
 *
 * This program is open source under the BSD-3 License.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <dpusm/provider_api.h> /* the DPUSM provider API */
#include <qat.h>				/* QAT wrapper from ZFS */

/* should not be here */
#include <sys/abd.h>
#include <sys/spa_checksum.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_raidz.h>
#include <sys/vdev_raidz_impl.h>
#include <sys/zfs_file.h>
#include <sys/zio.h>

typedef enum zfs_qat_handle_type {
	ZQH_REAL,
	ZQH_REF,
} zqh_type_t;

typedef struct zfs_qat_provider_handle {
	zqh_type_t type;
	void *ptr;
	size_t size;
} zqh_t;

static void *
ptr_start(zqh_t *zqh, const size_t offset)
{
	return (((char *)zqh->ptr) + offset);
}

static int
zfs_qat_provider_algorithms(int *compress, int *decompress,
    int *checksum, int *checksum_byteorder, int *raid)
{
	*compress =
	    DPUSM_COMPRESS_GZIP_1 |
	    DPUSM_COMPRESS_GZIP_2 |
	    DPUSM_COMPRESS_GZIP_3 |
	    DPUSM_COMPRESS_GZIP_4 |
	    DPUSM_COMPRESS_GZIP_5 |
	    DPUSM_COMPRESS_GZIP_6 |
	    DPUSM_COMPRESS_GZIP_7 |
	    DPUSM_COMPRESS_GZIP_8 |
	    DPUSM_COMPRESS_GZIP_9;

	*decompress = *compress;

	*checksum = DPUSM_CHECKSUM_SHA256 | DPUSM_CHECKSUM_SHA512;

	*checksum_byteorder = DPUSM_BYTEORDER_NATIVE | DPUSM_BYTEORDER_BYTESWAP;

	*raid =
	    DPUSM_RAID_1_GEN |
	    DPUSM_RAID_2_GEN |
	    DPUSM_RAID_3_GEN |
	    DPUSM_RAID_1_REC |
	    DPUSM_RAID_2_REC |
	    DPUSM_RAID_3_REC;

	return (DPUSM_OK);
}

static void *
zfs_qat_provider_alloc(size_t size)
{
	zqh_t *buf = kmalloc(sizeof (zqh_t), GFP_KERNEL);
	buf->type = ZQH_REAL;
	buf->ptr = kmalloc(size, GFP_KERNEL);
	buf->size = size;
	return (buf);
}

static void *
zfs_qat_provider_alloc_ref(void *src_handle, size_t offset, size_t size)
{
	zqh_t *src = (zqh_t *)src_handle;

	zqh_t *ref = kmalloc(sizeof (zqh_t), GFP_KERNEL);
	ref->type = ZQH_REF;
	ref->ptr = ptr_start(src, offset);
	ref->size = size;

	return (ref);
}

static int
zfs_qat_provider_get_size(void *handle, size_t *size, size_t *actual)
{
	zqh_t *buf = (zqh_t *)handle;
	if (size) {
		*size = buf->size;
	}

	if (actual) {
		*actual = buf->size;
	}

	return (DPUSM_OK);
}

static int
zfs_qat_provider_free(void *handle)
{
	zqh_t *buf = (zqh_t *)handle;
	if (buf->type == ZQH_REAL) {
		kfree(buf->ptr);
	}
	kfree(buf);

	return (DPUSM_OK);
}

static int
zfs_qat_provider_copy_from_generic(dpusm_mv_t *mv, const void *buf, size_t size)
{
	memcpy(ptr_start(mv->handle, mv->offset), buf, size);
	return (DPUSM_OK);
}

static int
zfs_qat_provider_copy_to_generic(dpusm_mv_t *mv, void *buf, size_t size)
{
	memcpy(buf, ptr_start(mv->handle, mv->offset), size);
	return (DPUSM_OK);
}

static int
zfs_qat_provider_zero_fill(void *handle, size_t offset, size_t size)
{
	memset(ptr_start(handle, offset), 0, size);
	return (DPUSM_ERROR);
}

static int
zfs_qat_provider_all_zeros(void *handle, size_t offset, size_t size)
{
	zqh_t *zqh = (zqh_t *)handle;
	for (size_t i = 0; i < size; i++) {
		if (((char *)zqh->ptr)[offset + i]) {
			return (DPUSM_ERROR);
		}
	}
	return (DPUSM_OK);
}

static int
zfs_qat_provider_compress(dpusm_compress_t alg, int level,
    void *src, size_t s_len, void *dst, size_t *d_len)
{
	(void) alg;   /* unused */
	(void) level; /* unused */

	/* check if hardware accelerator can be used */
	if (!qat_dc_use_accel(s_len)) {
		return (DPUSM_ERROR);
	}

	zqh_t *s = (zqh_t *)src;
	zqh_t *d = (zqh_t *)dst;

	if ((s_len > s->size) ||
	    (*d_len > d->size)) {
		return (DPUSM_ERROR);
	}

	void *s_start = ptr_start(s, 0);
	void *d_start = ptr_start(d, 0);

	const int ret = qat_compress(QAT_COMPRESS,
	    s_start, s_len, d_start, *d_len, d_len);
	if (ret == CPA_STATUS_SUCCESS) {
		return (DPUSM_OK);
	} else if (ret == CPA_STATUS_INCOMPRESSIBLE) {
		*d_len = s_len;
		return (DPUSM_OK);
	}
	return (DPUSM_ERROR);
}

static int
zfs_qat_provider_decompress(dpusm_compress_t alg, int *level,
    void *src, size_t s_len, void *dst, size_t *d_len)
{
	(void) alg;   /* unused */
	(void) level; /* unused */

	/* check if hardware accelerator can be used */
	if (!qat_dc_use_accel(d_len)) {
		return (DPUSM_ERROR);
	}

	zqh_t *s = (zqh_t *)src;
	zqh_t *d = (zqh_t *)dst;

	if ((s_len > s->size) ||
	    (*d_len > d->size)) {
		return (DPUSM_ERROR);
	}

	void *s_start = ptr_start(s, 0);
	void *d_start = ptr_start(d, 0);

	if (qat_compress(QAT_DECOMPRESS, s_start, s_len,
	    d_start, *d_len, d_len) == CPA_STATUS_SUCCESS) {
		return (DPUSM_OK);
	}

	return (DPUSM_ERROR);
}

static int
zfs_qat_provider_checksum(dpusm_checksum_t alg,
    dpusm_checksum_byteorder_t order, void *data, size_t size,
    void *cksum, size_t cksum_size)
{
	(void) order; /* might have to handle here */

	if (!qat_checksum_use_accel(size)) {
		return (DPUSM_ERROR);
	}

	if (alg != DPUSM_CHECKSUM_SHA256) {
		return (DPUSM_NOT_IMPLEMENTED);
	}

	if (cksum_size < sizeof (zio_cksum_t)) {
		return (DPUSM_ERROR);
	}

	zqh_t *src = (zqh_t *)data;
	if (size > src->size) {
		return (DPUSM_ERROR);
	}

	const int ret = qat_checksum(ZIO_CHECKSUM_SHA256, src->ptr, size,
	    cksum);
	return ((ret == CPA_STATUS_SUCCESS)?DPUSM_OK:DPUSM_ERROR);
}

static int
zfs_qat_provider_raidz_can_compute(size_t nparity, size_t ndata,
    size_t *col_sizes, int rec)
{
	if ((nparity < 1) || (nparity > 3)) {
		return (DPUSM_NOT_SUPPORTED);
	}

	return (DPUSM_OK);
}

static void *
zfs_qat_provider_raidz_alloc(size_t nparity, size_t ndata)
{
	const size_t ncols = nparity + ndata;

	const size_t rr_size = offsetof(raidz_row_t, rr_col[ncols]);
	raidz_row_t *rr = kzalloc(rr_size, GFP_KERNEL);
	rr->rr_cols = ncols;
	rr->rr_firstdatacol = nparity;

	return (rr);
}

/* attaches a column to the raidz struct */
static int
zfs_qat_provider_raidz_set_column(void *raidz, uint64_t c,
    void *col, size_t size)
{
	raidz_row_t *rr = (raidz_row_t *)raidz;
	zqh_t *zqh = (zqh_t *)col;

	if (!rr || !zqh) {
		return (DPUSM_ERROR);
	}

	/* c is too big */
	if (c >= rr->rr_cols) {
		return (DPUSM_ERROR);
	}

	/* "active" size is larger than allocated size */
	if (size > zqh->size) {
		return (DPUSM_ERROR);
	}

	raidz_col_t *rc = &rr->rr_col[c];

	/* clean up old column */
	abd_free(rc->rc_abd);

	/*
	 * rc->rc_abd does not take ownership of zqh->ptr,
	 * so don't need to release ownership
	 */
	rc->rc_abd = abd_get_from_buf(zqh->ptr, size);
	rc->rc_size = size;

	return (DPUSM_OK);
}

static int
zfs_qat_provider_raidz_free(void *raidz)
{
	raidz_row_t *rr = (raidz_row_t *)raidz;
	for (int c = 0; c < rr->rr_cols; c++) {
		raidz_col_t *rc = &rr->rr_col[c];
		abd_free(rc->rc_abd);
	}
	kfree(rr);

	return (DPUSM_OK);
}

static int
zfs_qat_provider_raidz_gen(void *raidz)
{
	raidz_row_t *rr = (raidz_row_t *)raidz;
	switch (rr->rr_firstdatacol) {
		case 1:
			vdev_raidz_generate_parity_p(rr);
			break;
		case 2:
			vdev_raidz_generate_parity_pq(rr);
			break;
		case 3:
			vdev_raidz_generate_parity_pqr(rr);
			break;
	}

	return (DPUSM_OK);
}

static int
zfs_qat_provider_raidz_rec(void *raidz, int *tgts, int ntgts)
{
	raidz_row_t *rr = (raidz_row_t *)raidz;
	vdev_raidz_reconstruct_general(rr, tgts, ntgts);

	return (DPUSM_OK);
}

static int
zfs_qat_provider_raidz_cmp(void *lhs_handle, void *rhs_handle, int *diff)
{
	zqh_t *lhs = (zqh_t *)lhs_handle;
	zqh_t *rhs = (zqh_t *)rhs_handle;

	if (!diff) {
		return (DPUSM_ERROR);
	}

	size_t len = rhs->size;
	if (lhs->size != rhs->size) {
		len =
		    (lhs->size < rhs->size)?lhs->size:rhs->size;
	}

	*diff = memcmp(ptr_start(lhs, 0),
	    ptr_start(rhs, 0), len);

	return (DPUSM_OK);
}

static void *
zfs_qat_provider_file_open(const char *path, int flags, int mode)
{
	zfs_file_t *fp = NULL;
	/* on error, fp should still be NULL */
	zfs_file_open(path, flags, mode, &fp);
	return (fp);
}

static int
zfs_qat_provider_file_write(void *fp_handle, void *handle, size_t count,
    size_t trailing_zeros, loff_t offset, ssize_t *resid, int *err)
{
	zfs_file_t *fp = (zfs_file_t *)fp_handle;
	zqh_t *zqh = (zqh_t *)handle;

	if (!err) {
		return (EIO);
	}

	*err = zfs_file_pwrite(fp, ptr_start(zqh, 0),
	    count, offset, resid);

	if (*err == 0) {
		void *zeros = kzalloc(trailing_zeros, GFP_KERNEL);
		*err = zfs_file_pwrite(fp, zeros,
		    trailing_zeros, offset + count, resid);
		kfree(zeros);
	}

	return (*err);
}

static void
zfs_qat_provider_file_close(void *fp_handle)
{
	zfs_file_close(fp_handle);
}

static void *
zfs_qat_provider_disk_open(dpusm_dd_t *disk_data)
{
	return (disk_data->bdev);
}

static int
zfs_qat_provider_disk_invalidate(void *disk_handle)
{
	struct block_device *bdev =
	    (struct block_device *)disk_handle;
	invalidate_bdev(bdev);
	return (DPUSM_OK);
}

static int
zfs_qat_provider_disk_write(void *disk_handle, void *handle, size_t data_size,
    size_t trailing_zeros, uint64_t io_offset, int flags,
    dpusm_disk_write_completion_t write_completion, void *wc_args)
{
	struct block_device *bdev =
	    (struct block_device *)disk_handle;
	zqh_t *zqh = (zqh_t *)handle;

	const size_t io_size = data_size + trailing_zeros;

	if (trailing_zeros) {
		/* create a copy of the data with the trailing zeros attached */
		void *copy = kzalloc(io_size, GFP_KERNEL);
		memcpy(copy, ptr_start(zqh, 0), data_size);

		/* need to keep copy alive, so replace zqh->ptr */
		if (zqh->type == ZQH_REAL) {
			kfree(zqh->ptr);
		}

		zqh->type = ZQH_REAL;
		zqh->ptr = copy;
		zqh->size = io_size;
	}

	abd_t *abd = abd_get_from_buf(zqh->ptr, io_size);
	zio_push_transform(wc_args, abd, io_size, io_size, NULL);

	/* __vdev_disk_physio already adds write_completion */
	(void) write_completion;

	return (__vdev_disk_physio(bdev, wc_args,
	    io_size, io_offset, WRITE, flags));
}

static int
zfs_qat_provider_disk_flush(void *disk_handle,
    dpusm_disk_flush_completion_t flush_completion, void *fc_args)
{
	struct block_device *bdev =
	    (struct block_device *)disk_handle;

	/* vdev_disk_io_flush already adds flush completion */
	(void) flush_completion;

	return (vdev_disk_io_flush(bdev, fc_args));
}

static void
zfs_qat_provider_disk_close(void *disk_handle)
{}

/*
 * "zfs-qat-provider" instead of "qat-provider"
 * because this provider links with ZFS symbols
 */
/* BEGIN CSTYLED */
static const char name[] = "zfs-qat-provider";
static const dpusm_pf_t zfs_qat_provider_functions = {
	.algorithms           = zfs_qat_provider_algorithms,
	.alloc                = zfs_qat_provider_alloc,
	.alloc_ref            = zfs_qat_provider_alloc_ref,
	.get_size             = zfs_qat_provider_get_size,
	.free                 = zfs_qat_provider_free,
	.copy                 = {
	                            .from = {
	                                        .generic      = zfs_qat_provider_copy_from_generic,
	                                        .ptr          = NULL,
	                                        .scatterlist  = NULL,
	                                    },
	                            .to   = {
	                                        .generic      = zfs_qat_provider_copy_to_generic,
	                                        .ptr          = NULL,
	                                        .scatterlist  = NULL,
	                                    },
	                        },
	.mem_stats            = NULL,
	.zero_fill            = zfs_qat_provider_zero_fill,
	.all_zeros            = zfs_qat_provider_all_zeros,
	.compress             = zfs_qat_provider_compress,
	.decompress           = zfs_qat_provider_decompress,
	.checksum             = zfs_qat_provider_checksum,
	.raid                 = {
                                .can_compute = zfs_qat_provider_raidz_can_compute,
	                            .alloc       = zfs_qat_provider_raidz_alloc,
	                            .set_column  = zfs_qat_provider_raidz_set_column,
	                            .free        = zfs_qat_provider_raidz_free,
	                            .gen         = zfs_qat_provider_raidz_gen,
	                            .cmp         = zfs_qat_provider_raidz_cmp,
	                            .rec         = zfs_qat_provider_raidz_rec,
	                        },
	.file                 = {
	                            .open        = zfs_qat_provider_file_open,
	                            .write       = zfs_qat_provider_file_write,
	                            .close       = zfs_qat_provider_file_close,
	                        },
	.disk                 = {
	                            .open        = zfs_qat_provider_disk_open,
	                            .invalidate  = zfs_qat_provider_disk_invalidate,
	                            .write       = zfs_qat_provider_disk_write,
	                            .flush       = zfs_qat_provider_disk_flush,
	                            .close       = zfs_qat_provider_disk_close,
	                        },
};
/* END CSTYLED */

static int __init
zfs_qat_provider_init(void)
{
	if ((qat_dc_init() != 0) ||
	    (qat_cy_init() != 0)) {
		qat_cy_fini();
		qat_dc_fini();
		return (-EFAULT);
	}

	return (dpusm_register_bsd(name, &zfs_qat_provider_functions));
}

static void __exit
zfs_qat_provider_exit(void)
{
	dpusm_unregister_bsd(name);

	qat_cy_fini();
	qat_dc_fini();
}

module_init(zfs_qat_provider_init);
module_exit(zfs_qat_provider_exit);

MODULE_LICENSE("CDDL");
