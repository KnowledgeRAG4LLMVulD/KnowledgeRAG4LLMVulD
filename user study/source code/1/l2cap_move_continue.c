static void l2cap_move_continue(struct l2cap_conn *conn, u16 icid, u16 result)
{
	struct l2cap_chan *chan;
	struct hci_chan *hchan = NULL;

	chan = l2cap_get_chan_by_scid(conn, icid);
	if (!chan)
	{
		l2cap_send_move_chan_cfm_icid(conn, icid);
		return;
	}

	__clear_chan_timer(chan);
	if (result == L2CAP_MR_PEND)
		__set_chan_timer(chan, L2CAP_MOVE_ERTX_TIMEOUT);

	switch (chan->move_state)
	{
	case L2CAP_MOVE_WAIT_LOGICAL_COMP:
		/* Move confirm will be sent when logical link
		 * is complete.
		 */
		chan->move_state = L2CAP_MOVE_WAIT_LOGICAL_CFM;
		break;
	case L2CAP_MOVE_WAIT_RSP_SUCCESS:
		if (result == L2CAP_MR_PEND)
		{
			break;
		}
		else if (test_bit(CONN_LOCAL_BUSY,
						  &chan->conn_state))
		{
			chan->move_state = L2CAP_MOVE_WAIT_LOCAL_BUSY;
		}
		else
		{
			/* Logical link is up or moving to BR/EDR,
			 * proceed with move
			 */
			chan->move_state = L2CAP_MOVE_WAIT_CONFIRM_RSP;
			l2cap_send_move_chan_cfm(chan, L2CAP_MC_CONFIRMED);
		}
		break;
	case L2CAP_MOVE_WAIT_RSP:
		/* Moving to AMP */
		if (result == L2CAP_MR_SUCCESS)
		{
			/* Remote is ready, send confirm immediately
			 * after logical link is ready
			 */
			chan->move_state = L2CAP_MOVE_WAIT_LOGICAL_CFM;
		}
		else
		{
			/* Both logical link and move success
			 * are required to confirm
			 */
			chan->move_state = L2CAP_MOVE_WAIT_LOGICAL_COMP;
		}

		/* Placeholder - get hci_chan for logical link */
		if (!hchan)
		{
			/* Logical link not available */
			l2cap_send_move_chan_cfm(chan, L2CAP_MC_UNCONFIRMED);
			break;
		}

		/* If the logical link is not yet connected, do not
		 * send confirmation.
		 */
		if (hchan->state != BT_CONNECTED)
			break;

		/* Logical link is already ready to go */

		chan->hs_hcon = hchan->conn;
		chan->hs_hcon->l2cap_data = chan->conn;

		if (result == L2CAP_MR_SUCCESS)
		{
			/* Can confirm now */
			l2cap_send_move_chan_cfm(chan, L2CAP_MC_CONFIRMED);
		}
		else
		{
			/* Now only need move success
			 * to confirm
			 */
			chan->move_state = L2CAP_MOVE_WAIT_RSP_SUCCESS;
		}

		l2cap_logical_cfm(chan, hchan, L2CAP_MR_SUCCESS);
		break;
	default:
		/* Any other amp move state means the move failed. */
		chan->move_id = chan->local_amp_id;
		l2cap_move_done(chan);
		l2cap_send_move_chan_cfm(chan, L2CAP_MC_UNCONFIRMED);
	}

	l2cap_chan_unlock(chan);
	l2cap_chan_put(chan);
}