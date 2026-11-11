/* Fills the context the way imsd_sip_init() would, for the recorded LG U+ values. */
#define GOLDEN_DOMAIN "lte-lguplus.co.kr"

static void golden_setup(struct imsd_sip_ctx *ctx, sd_event *event, int ue_fd,
			 const struct sockaddr_in6 *pcscf)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->event = event;
	ctx->fd = ue_fd;
	ctx->rtp_fd = -1;
	ctx->reg_state = IMSD_DOWN;
	ctx->call_state = IMSD_CALL_IDLE;
	snprintf(ctx->impi, sizeof(ctx->impi), "450061234567890@" GOLDEN_DOMAIN);
	snprintf(ctx->impu, sizeof(ctx->impu), "sip:01000000000@" GOLDEN_DOMAIN);
	snprintf(ctx->impu_user, sizeof(ctx->impu_user), "01000000000");
	snprintf(ctx->local_ip, sizeof(ctx->local_ip), "::1");
	ctx->pcscf_addr = *pcscf;
	rand_hex(ctx->reg_from_tag, 8);
	char cid_rnd[32];
	rand_hex(cid_rnd, 16);
	snprintf(ctx->reg_call_id, sizeof(ctx->reg_call_id), "%s@" GOLDEN_DOMAIN, cid_rnd);
	ctx->reg_cseq = 1;
}
