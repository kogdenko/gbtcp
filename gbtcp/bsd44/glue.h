#ifndef GBTCP_BSD44_GLUE_H
#define GBTCP_BSD44_GLUE_H

int bsd_mod_init(void);
void bsd_mod_deinit(void);
void bsd_mod_timer(struct timer *timer, u_char fn_id);

#endif
