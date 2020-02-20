/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASHCAT_H
#define _HASHCAT_H

int   hashcat_init               (hashcat_ctx_t *hashcat_ctx, void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t));
void  hashcat_destroy            (hashcat_ctx_t *hashcat_ctx);

int   hashcat_session_init       (hashcat_ctx_t *hashcat_ctx, const char *install_folder, const char *shared_folder, int argc, char **argv, const int comptime);
int   hashcat_session_execute    (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_pause      (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_resume     (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_bypass     (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_checkpoint (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_quit       (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_destroy    (hashcat_ctx_t *hashcat_ctx);

char *hashcat_get_log            (hashcat_ctx_t *hashcat_ctx);
int   hashcat_get_status         (hashcat_ctx_t *hashcat_ctx, hashcat_status_t *hashcat_status);

int  init_bcryptengine();
void exit_bcryptengine();
int  get_enginecount();

int  bcrypt_hashpass(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);

int  bcrypt_hashpass01(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass02(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass03(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass04(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass05(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass06(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass07(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass08(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass09(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass10(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass11(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass12(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass13(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass14(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass15(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);
int  bcrypt_hashpass16(const char* pwd,const char* insolt, int nround , char* outhash, int nchanal);






int   maintest(char* pwd, char* insolt, int nround);

#endif // _HASHCAT_H
