int v4l2_m2m_prepare_buf(struct file *file, struct v4l2_m2m_ctx *m2m_ctx,
                         struct v4l2_buffer *buf)
{
    struct video_device *vdev = video_devdata(file);
    struct vb2_queue *vq;
    int ret;

    vq = v4l2_m2m_get_vq(m2m_ctx, buf->type);
    ret = vb2_prepare_buf(vq, vdev->v4l2_dev->mdev, buf);
    if (ret)
        return ret;

    /* Adjust MMAP memory offsets for the CAPTURE queue */
    v4l2_m2m_adjust_mem_offset(vq, buf);

    return 0;
}
EXPORT_SYMBOL_GPL(v4l2_m2m_prepare_buf);