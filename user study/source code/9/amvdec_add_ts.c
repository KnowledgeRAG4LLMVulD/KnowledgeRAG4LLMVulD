void amvdec_add_ts(struct amvdec_session *sess, u64 ts,
                   struct v4l2_timecode tc, u32 offset, u32 vbuf_flags)
{
    struct amvdec_timestamp *new_ts;
    unsigned long flags;

    new_ts = kzalloc(sizeof(*new_ts), GFP_KERNEL);
    new_ts->ts = ts;
    new_ts->tc = tc;
    new_ts->offset = offset;
    new_ts->flags = vbuf_flags;

    spin_lock_irqsave(&sess->ts_spinlock, flags);
    list_add_tail(&new_ts->list, &sess->timestamps);
    spin_unlock_irqrestore(&sess->ts_spinlock, flags);
}