static __be32
nfsd4_copy(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
           union nfsd4_op_u *u)
{
    struct nfsd4_copy *copy = &u->copy;
    __be32 status;
    struct nfsd4_copy *async_copy = NULL;

    if (nfsd4_ssc_is_inter(copy))
    {
        if (!inter_copy_offload_enable || nfsd4_copy_is_sync(copy))
        {
            status = nfserr_notsupp;
            goto out;
        }
        status = nfsd4_setup_inter_ssc(rqstp, cstate, copy,
                                       &copy->ss_mnt);
        if (status)
            return nfserr_offload_denied;
    }
    else
    {
        status = nfsd4_setup_intra_ssc(rqstp, cstate, copy);
        if (status)
            return status;
    }

    copy->cp_clp = cstate->clp;
    memcpy(&copy->fh, &cstate->current_fh.fh_handle,
           sizeof(struct knfsd_fh));
    if (nfsd4_copy_is_async(copy))
    {
        struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

        status = nfserrno(-ENOMEM);
        async_copy = kzalloc(sizeof(struct nfsd4_copy), GFP_KERNEL);
        if (!async_copy)
            goto out_err;
        async_copy->cp_src = kmalloc(sizeof(*async_copy->cp_src), GFP_KERNEL);
        if (!async_copy->cp_src)
            goto out_err;
        if (!nfs4_init_copy_state(nn, copy))
            goto out_err;
        refcount_set(&async_copy->refcount, 1);
        memcpy(&copy->cp_res.cb_stateid, &copy->cp_stateid.cs_stid,
               sizeof(copy->cp_res.cb_stateid));
        dup_copy_fields(copy, async_copy);
        async_copy->copy_task = kthread_create(nfsd4_do_async_copy,
                                               async_copy, "%s", "copy thread");
        if (IS_ERR(async_copy->copy_task))
            goto out_err;
        spin_lock(&async_copy->cp_clp->async_lock);
        list_add(&async_copy->copies,
                 &async_copy->cp_clp->async_copies);
        spin_unlock(&async_copy->cp_clp->async_lock);
        wake_up_process(async_copy->copy_task);
        status = nfs_ok;
    }
    else
    {
        status = nfsd4_do_copy(copy, copy->nf_src->nf_file,
                               copy->nf_dst->nf_file, true);
        nfsd4_cleanup_intra_ssc(copy->nf_src, copy->nf_dst);
    }
out:
    return status;
out_err:
    if (async_copy)
        cleanup_async_copy(async_copy);
    status = nfserrno(-ENOMEM);
    if (nfsd4_ssc_is_inter(copy))
        nfsd4_interssc_disconnect(copy->ss_mnt);
    goto out;
}