#include "spu_runtime.h"

extern void spu_run_sre_a(SPUContext*);
extern const uint32_t spu_run_sre_a_range[2];
extern const uint32_t spu_run_sre_a_sigat;
extern const uint8_t spu_run_sre_a_sig[16];
extern void spu_run_sre_b(SPUContext*);
extern const uint32_t spu_run_sre_b_range[2];
extern const uint32_t spu_run_sre_b_sigat;
extern const uint8_t spu_run_sre_b_sig[16];
extern void spu_run_ss(SPUContext*);
extern const uint32_t spu_run_ss_range[2];
extern const uint32_t spu_run_ss_sigat;
extern const uint8_t spu_run_ss_sig[16];
extern void spu_run_jc(SPUContext*);
extern const uint32_t spu_run_jc_range[2];
extern const uint32_t spu_run_jc_sigat;
extern const uint8_t spu_run_jc_sig[16];
extern void spu_run_p3(SPUContext*);
extern const uint32_t spu_run_p3_range[2];
extern const uint32_t spu_run_p3_sigat;
extern const uint8_t spu_run_p3_sig[16];
extern void spu_job_c06a80(SPUContext*);
extern const uint32_t spu_job_c06a80_range[2];
extern const uint32_t spu_job_c06a80_sigat;
extern const uint8_t spu_job_c06a80_sig[16];
extern void spu_job_d08180(SPUContext*);
extern const uint32_t spu_job_d08180_range[2];
extern const uint32_t spu_job_d08180_sigat;
extern const uint8_t spu_job_d08180_sig[16];
extern void spu_task_a(SPUContext*);
extern const uint32_t spu_task_a_range[2];
extern const uint32_t spu_task_a_sigat;
extern const uint8_t spu_task_a_sig[16];
extern void spu_auto_d3a180(SPUContext*);
extern const uint32_t spu_auto_d3a180_range[2];
extern const uint32_t spu_auto_d3a180_sigat;
extern const uint8_t spu_auto_d3a180_sig[16];
extern void spu_auto_d42600(SPUContext*);
extern const uint32_t spu_auto_d42600_range[2];
extern const uint32_t spu_auto_d42600_sigat;
extern const uint8_t spu_auto_d42600_sig[16];
extern void spu_auto_1e020380(SPUContext*);
extern const uint32_t spu_auto_1e020380_range[2];
extern const uint32_t spu_auto_1e020380_sigat;
extern const uint8_t spu_auto_1e020380_sig[16];
extern void spu_auto_1e020c00(SPUContext*);
extern const uint32_t spu_auto_1e020c00_range[2];
extern const uint32_t spu_auto_1e020c00_sigat;
extern const uint8_t spu_auto_1e020c00_sig[16];
extern void spu_job_c46680(SPUContext*);
extern const uint32_t spu_job_c46680_range[2];
extern const uint32_t spu_job_c46680_sigat;
extern const uint8_t spu_job_c46680_sig[16];
extern void spu_job_cfcf80(SPUContext*);
extern const uint32_t spu_job_cfcf80_range[2];
extern const uint32_t spu_job_cfcf80_sigat;
extern const uint8_t spu_job_cfcf80_sig[16];
extern void spu_job_d08180_b(SPUContext*);
extern const uint32_t spu_job_d08180_b_range[2];
extern const uint32_t spu_job_d08180_b_sigat;
extern const uint8_t spu_job_d08180_b_sig[16];
extern void spu_run_jq(SPUContext*);
extern const uint32_t spu_run_jq_range[2];
extern const uint32_t spu_run_jq_sigat;
extern const uint8_t spu_run_jq_sig[16];
extern void spu_job_c2aa00(SPUContext*);
extern const uint32_t spu_job_c2aa00_range[2];
extern const uint32_t spu_job_c2aa00_sigat;
extern const uint8_t spu_job_c2aa00_sig[16];
extern void spu_job_c05d00(SPUContext*);
extern const uint32_t spu_job_c05d00_range[2];
extern const uint32_t spu_job_c05d00_sigat;
extern const uint8_t spu_job_c05d00_sig[16];
extern void spu_job_pac1(SPUContext*);
extern const uint32_t spu_job_pac1_range[2];
extern const uint32_t spu_job_pac1_sigat;
extern const uint8_t spu_job_pac1_sig[16];
extern void spu_job_c17780(SPUContext*);
extern const uint32_t spu_job_c17780_range[2];
extern const uint32_t spu_job_c17780_sigat;
extern const uint8_t spu_job_c17780_sig[16];
extern void spu_job_c2cf80(SPUContext*);
extern const uint32_t spu_job_c2cf80_range[2];
extern const uint32_t spu_job_c2cf80_sigat;
extern const uint8_t spu_job_c2cf80_sig[16];
extern void spu_job_c3f400(SPUContext*);
extern const uint32_t spu_job_c3f400_range[2];
extern const uint32_t spu_job_c3f400_sigat;
extern const uint8_t spu_job_c3f400_sig[16];
extern void spu_job_c43c00(SPUContext*);
extern const uint32_t spu_job_c43c00_range[2];
extern const uint32_t spu_job_c43c00_sigat;
extern const uint8_t spu_job_c43c00_sig[16];
extern void spu_job_cfcf80_b(SPUContext*);
extern const uint32_t spu_job_cfcf80_b_range[2];
extern const uint32_t spu_job_cfcf80_b_sigat;
extern const uint8_t spu_job_cfcf80_b_sig[16];
extern void spu_job_c14a80(SPUContext*);
extern const uint32_t spu_job_c14a80_range[2];
extern const uint32_t spu_job_c14a80_sigat;
extern const uint8_t spu_job_c14a80_sig[16];
extern void spu_job_beff00(SPUContext*);
extern const uint32_t spu_job_beff00_range[2];
extern const uint32_t spu_job_beff00_sigat;
extern const uint8_t spu_job_beff00_sig[16];
extern void spu_job_c1eb80(SPUContext*);
extern const uint32_t spu_job_c1eb80_range[2];
extern const uint32_t spu_job_c1eb80_sigat;
extern const uint8_t spu_job_c1eb80_sig[16];
extern void spu_job_ca3480(SPUContext*);
extern const uint32_t spu_job_ca3480_range[2];
extern const uint32_t spu_job_ca3480_sigat;
extern const uint8_t spu_job_ca3480_sig[16];
extern void spu_job_cfcf80_c(SPUContext*);
extern const uint32_t spu_job_cfcf80_c_range[2];
extern const uint32_t spu_job_cfcf80_c_sigat;
extern const uint8_t spu_job_cfcf80_c_sig[16];
extern void spu_job_c8cb80(SPUContext*);
extern const uint32_t spu_job_c8cb80_range[2];
extern const uint32_t spu_job_c8cb80_sigat;
extern const uint8_t spu_job_c8cb80_sig[16];
extern void spu_job_c1b200(SPUContext*);
extern const uint32_t spu_job_c1b200_range[2];
extern const uint32_t spu_job_c1b200_sigat;
extern const uint8_t spu_job_c1b200_sig[16];
extern void spu_job_c61380(SPUContext*);
extern const uint32_t spu_job_c61380_range[2];
extern const uint32_t spu_job_c61380_sigat;
extern const uint8_t spu_job_c61380_sig[16];
extern void spu_job_c41a00(SPUContext*);
extern const uint32_t spu_job_c41a00_range[2];
extern const uint32_t spu_job_c41a00_sigat;
extern const uint8_t spu_job_c41a00_sig[16];
extern void spu_job_c27800(SPUContext*);
extern const uint32_t spu_job_c27800_range[2];
extern const uint32_t spu_job_c27800_sigat;
extern const uint8_t spu_job_c27800_sig[16];
extern void spu_job_c47380(SPUContext*);
extern const uint32_t spu_job_c47380_range[2];
extern const uint32_t spu_job_c47380_sigat;
extern const uint8_t spu_job_c47380_sig[16];
extern void spu_job_bfa000(SPUContext*);
extern const uint32_t spu_job_bfa000_range[2];
extern const uint32_t spu_job_bfa000_sigat;
extern const uint8_t spu_job_bfa000_sig[16];
extern void spu_job_c62580(SPUContext*);
extern const uint32_t spu_job_c62580_range[2];
extern const uint32_t spu_job_c62580_sigat;
extern const uint8_t spu_job_c62580_sig[16];
extern void spu_job_c91780(SPUContext*);
extern const uint32_t spu_job_c91780_range[2];
extern const uint32_t spu_job_c91780_sigat;
extern const uint8_t spu_job_c91780_sig[16];
extern void spu_job_cb0f00(SPUContext*);
extern const uint32_t spu_job_cb0f00_range[2];
extern const uint32_t spu_job_cb0f00_sigat;
extern const uint8_t spu_job_cb0f00_sig[16];
extern void spu_job_cb0f00_s1b400(SPUContext*);
extern const uint32_t spu_job_cb0f00_s1b400_range[2];
extern const uint32_t spu_job_cb0f00_s1b400_sigat;
extern const uint8_t spu_job_cb0f00_s1b400_sig[16];
extern void spu_job_cb0f00_s1d000(SPUContext*);
extern const uint32_t spu_job_cb0f00_s1d000_range[2];
extern const uint32_t spu_job_cb0f00_s1d000_sigat;
extern const uint8_t spu_job_cb0f00_s1d000_sig[16];
static const uint32_t cb0f00_s1d000_range_clamped[2] = {0x1d000, 0x3d000};
extern void spu_job_ca3480_b(SPUContext*);
extern const uint32_t spu_job_ca3480_b_range[2];
extern const uint32_t spu_job_ca3480_b_sigat;
extern const uint8_t spu_job_ca3480_b_sig[16];

extern void spu_job_ca3480_s22400(SPUContext*);
extern const uint32_t spu_job_ca3480_s22400_range[2];
extern const uint32_t spu_job_ca3480_s22400_sigat;
extern const uint8_t spu_job_ca3480_s22400_sig[16];

extern void spu_job_d1cd00_s7c00(SPUContext*);
extern const uint32_t spu_job_d1cd00_s7c00_range[2];
extern const uint32_t spu_job_d1cd00_s7c00_sigat;
extern const uint8_t spu_job_d1cd00_s7c00_sig[16];
extern void spu_job_d0da00_s7c00(SPUContext*);
extern const uint32_t spu_job_d0da00_s7c00_range[2];
extern const uint32_t spu_job_d0da00_s7c00_sigat;
extern const uint8_t spu_job_d0da00_s7c00_sig[16];
extern void spu_job_ca3480_s1e400(SPUContext*);
extern const uint32_t spu_job_ca3480_s1e400_range[2];
extern const uint32_t spu_job_ca3480_s1e400_sigat;
extern const uint8_t spu_job_ca3480_s1e400_sig[16];
extern void spu_job_ca3480_s21800(SPUContext*);
extern const uint32_t spu_job_ca3480_s21800_range[2];
extern const uint32_t spu_job_ca3480_s21800_sigat;
extern const uint8_t spu_job_ca3480_s21800_sig[16];
extern void spu_job_ca3480_s21c00(SPUContext*);
extern const uint32_t spu_job_ca3480_s21c00_range[2];
extern const uint32_t spu_job_ca3480_s21c00_sigat;
extern const uint8_t spu_job_ca3480_s21c00_sig[16];
extern void spu_job_ca3480_s22000(SPUContext*);
extern const uint32_t spu_job_ca3480_s22000_range[2];
extern const uint32_t spu_job_ca3480_s22000_sigat;
extern const uint8_t spu_job_ca3480_s22000_sig[16];
extern void spu_job_ca3480_s24800(SPUContext*);
extern const uint32_t spu_job_ca3480_s24800_range[2];
extern const uint32_t spu_job_ca3480_s24800_sigat;
extern const uint8_t spu_job_ca3480_s24800_sig[16];

extern void spu_job_c91780_s16800(SPUContext*);
extern const uint32_t spu_job_c91780_s16800_range[2];
extern const uint32_t spu_job_c91780_s16800_sigat;
extern const uint8_t spu_job_c91780_s16800_sig[16];
extern void spu_job_c91780_s16c00(SPUContext*);
extern const uint32_t spu_job_c91780_s16c00_range[2];
extern const uint32_t spu_job_c91780_s16c00_sigat;
extern const uint8_t spu_job_c91780_s16c00_sig[16];
extern void spu_job_c91780_s17000(SPUContext*);
extern const uint32_t spu_job_c91780_s17000_range[2];
extern const uint32_t spu_job_c91780_s17000_sigat;
extern const uint8_t spu_job_c91780_s17000_sig[16];
extern void spu_job_c91780_s17400(SPUContext*);
extern const uint32_t spu_job_c91780_s17400_range[2];
extern const uint32_t spu_job_c91780_s17400_sigat;
extern const uint8_t spu_job_c91780_s17400_sig[16];
extern void spu_job_c91780_s16400(SPUContext*);
extern const uint32_t spu_job_c91780_s16400_range[2];
extern const uint32_t spu_job_c91780_s16400_sigat;
extern const uint8_t spu_job_c91780_s16400_sig[16];
extern void spu_job_c91780_s5c00(SPUContext*);
extern const uint32_t spu_job_c91780_s5c00_range[2];
extern const uint32_t spu_job_c91780_s5c00_sigat;
extern const uint8_t spu_job_c91780_s5c00_sig[16];

extern void spu_run_jq_8000(SPUContext*);
extern const uint32_t spu_run_jq_8000_range[2];
extern const uint32_t spu_run_jq_8000_sigat;
extern const uint8_t spu_run_jq_8000_sig[16];
extern void spu_job_c8cb80_s5c00(SPUContext*);
extern const uint32_t spu_job_c8cb80_s5c00_range[2];
extern const uint32_t spu_job_c8cb80_s5c00_sigat;
extern const uint8_t spu_job_c8cb80_s5c00_sig[16];
extern void spu_job_c91780_s14000(SPUContext*);
extern const uint32_t spu_job_c91780_s14000_range[2];
extern const uint32_t spu_job_c91780_s14000_sigat;
extern const uint8_t spu_job_c91780_s14000_sig[16];
extern void spu_job_d1cd00_s37600(SPUContext*);
extern const uint32_t spu_job_d1cd00_s37600_range[2];
extern const uint32_t spu_job_d1cd00_s37600_sigat;
extern const uint8_t spu_job_d1cd00_s37600_sig[16];
extern void spu_job_ca3480_s1e800(SPUContext*);
extern const uint32_t spu_job_ca3480_s1e800_range[2];
extern const uint32_t spu_job_ca3480_s1e800_sigat;
extern const uint8_t spu_job_ca3480_s1e800_sig[16];
extern void spu_job_c91780_s15400(SPUContext*);
extern const uint32_t spu_job_c91780_s15400_range[2];
extern const uint32_t spu_job_c91780_s15400_sigat;
extern const uint8_t spu_job_c91780_s15400_sig[16];
extern void spu_job_ca3480_s24c00(SPUContext*);
extern const uint32_t spu_job_ca3480_s24c00_range[2];
extern const uint32_t spu_job_ca3480_s24c00_sigat;
extern const uint8_t spu_job_ca3480_s24c00_sig[16];
extern void spu_job_ca3480_s25000(SPUContext*);
extern const uint32_t spu_job_ca3480_s25000_range[2];
extern const uint32_t spu_job_ca3480_s25000_sigat;
extern const uint8_t spu_job_ca3480_s25000_sig[16];
extern void spu_job_cb0f00_s5c00(SPUContext*);
extern const uint32_t spu_job_cb0f00_s5c00_range[2];
extern const uint32_t spu_job_cb0f00_s5c00_sigat;
extern const uint8_t spu_job_cb0f00_s5c00_sig[16];
extern void spu_job_cb0f00_s17000(SPUContext*);
extern const uint32_t spu_job_cb0f00_s17000_range[2];
extern const uint32_t spu_job_cb0f00_s17000_sigat;
extern const uint8_t spu_job_cb0f00_s17000_sig[16];
extern void spu_job_ca3480_s16c00(SPUContext*);
extern const uint32_t spu_job_ca3480_s16c00_range[2];
extern const uint32_t spu_job_ca3480_s16c00_sigat;
extern const uint8_t spu_job_ca3480_s16c00_sig[16];
extern void spu_job_ca3480_s1ec00(SPUContext*);
extern const uint32_t spu_job_ca3480_s1ec00_range[2];
extern const uint32_t spu_job_ca3480_s1ec00_sigat;
extern const uint8_t spu_job_ca3480_s1ec00_sig[16];
extern void spu_job_ca3480_s1f000(SPUContext*);
extern const uint32_t spu_job_ca3480_s1f000_range[2];
extern const uint32_t spu_job_ca3480_s1f000_sigat;
extern const uint8_t spu_job_ca3480_s1f000_sig[16];
extern void spu_job_cb0f00_s1a800(SPUContext*);
extern const uint32_t spu_job_cb0f00_s1a800_range[2];
extern const uint32_t spu_job_cb0f00_s1a800_sigat;
extern const uint8_t spu_job_cb0f00_s1a800_sig[16];
extern void spu_job_cb0f00_s1cc00(SPUContext*);
extern const uint32_t spu_job_cb0f00_s1cc00_range[2];
extern const uint32_t spu_job_cb0f00_s1cc00_sigat;
extern const uint8_t spu_job_cb0f00_s1cc00_sig[16];
extern void spu_job_c91780_s2c800(SPUContext*);
extern const uint32_t spu_job_c91780_s2c800_range[2];
extern const uint32_t spu_job_c91780_s2c800_sigat;
extern const uint8_t spu_job_c91780_s2c800_sig[16];
extern void spu_job_c91780_s2cc00(SPUContext*);
extern const uint32_t spu_job_c91780_s2cc00_range[2];
extern const uint32_t spu_job_c91780_s2cc00_sigat;
extern const uint8_t spu_job_c91780_s2cc00_sig[16];

const SpuBody g_spu_bodies[] = {
  {0x818, spu_run_sre_a, spu_run_sre_a_range, &spu_run_sre_a_sigat, spu_run_sre_a_sig},
  {0x848, spu_run_sre_b, spu_run_sre_b_range, &spu_run_sre_b_sigat, spu_run_sre_b_sig},
  {0xa00, spu_run_ss, spu_run_ss_range, &spu_run_ss_sigat, spu_run_ss_sig},
  {0xa00, spu_run_jc, spu_run_jc_range, &spu_run_jc_sigat, spu_run_jc_sig},
  {0xa00, spu_run_p3, spu_run_p3_range, &spu_run_p3_sigat, spu_run_p3_sig},
  {0x4c00, spu_job_c06a80, spu_job_c06a80_range, &spu_job_c06a80_sigat, spu_job_c06a80_sig},
  {0x4c00, spu_job_d08180, spu_job_d08180_range, &spu_job_d08180_sigat, spu_job_d08180_sig},
  {0x3050, spu_task_a, spu_task_a_range, &spu_task_a_sigat, spu_task_a_sig},
  {0x3050, spu_auto_d3a180, spu_auto_d3a180_range, &spu_auto_d3a180_sigat, spu_auto_d3a180_sig},
  {0x3050, spu_auto_d42600, spu_auto_d42600_range, &spu_auto_d42600_sigat, spu_auto_d42600_sig},
  {0x818, spu_auto_1e020380, spu_auto_1e020380_range, &spu_auto_1e020380_sigat, spu_auto_1e020380_sig},
  {0x848, spu_auto_1e020c00, spu_auto_1e020c00_range, &spu_auto_1e020c00_sigat, spu_auto_1e020c00_sig},
  {0x4c00, spu_job_c46680, spu_job_c46680_range, &spu_job_c46680_sigat, spu_job_c46680_sig},
  {0x5800, spu_job_cfcf80, spu_job_cfcf80_range, &spu_job_cfcf80_sigat, spu_job_cfcf80_sig},
  {0xbc00, spu_job_d08180_b, spu_job_d08180_b_range, &spu_job_d08180_b_sigat, spu_job_d08180_b_sig},
  {0xa00, spu_run_jq, spu_run_jq_range, &spu_run_jq_sigat, spu_run_jq_sig},
  {0x4c00, spu_job_c2aa00, spu_job_c2aa00_range, &spu_job_c2aa00_sigat, spu_job_c2aa00_sig},
  {0x4c00, spu_job_c05d00, spu_job_c05d00_range, &spu_job_c05d00_sigat, spu_job_c05d00_sig},
  {0x4c00, spu_job_pac1, spu_job_pac1_range, &spu_job_pac1_sigat, spu_job_pac1_sig},
  {0x4c00, spu_job_c17780, spu_job_c17780_range, &spu_job_c17780_sigat, spu_job_c17780_sig},
  {0x4c00, spu_job_c2cf80, spu_job_c2cf80_range, &spu_job_c2cf80_sigat, spu_job_c2cf80_sig},
  {0x4c00, spu_job_c3f400, spu_job_c3f400_range, &spu_job_c3f400_sigat, spu_job_c3f400_sig},
  {0x4c00, spu_job_c43c00, spu_job_c43c00_range, &spu_job_c43c00_sigat, spu_job_c43c00_sig},
  {0x7800, spu_job_cfcf80_b, spu_job_cfcf80_b_range, &spu_job_cfcf80_b_sigat, spu_job_cfcf80_b_sig},
  {0x4c00, spu_job_c14a80, spu_job_c14a80_range, &spu_job_c14a80_sigat, spu_job_c14a80_sig},
  {0x4c00, spu_job_beff00, spu_job_beff00_range, &spu_job_beff00_sigat, spu_job_beff00_sig},
  {0x4c00, spu_job_c1eb80, spu_job_c1eb80_range, &spu_job_c1eb80_sigat, spu_job_c1eb80_sig},
  {0x4c00, spu_job_ca3480, spu_job_ca3480_range, &spu_job_ca3480_sigat, spu_job_ca3480_sig},
  {0x4c00, spu_job_cfcf80_c, spu_job_cfcf80_c_range, &spu_job_cfcf80_c_sigat, spu_job_cfcf80_c_sig},
  {0x4c00, spu_job_c8cb80, spu_job_c8cb80_range, &spu_job_c8cb80_sigat, spu_job_c8cb80_sig},
  {0x4c00, spu_job_c1b200, spu_job_c1b200_range, &spu_job_c1b200_sigat, spu_job_c1b200_sig},
  {0x4c00, spu_job_c61380, spu_job_c61380_range, &spu_job_c61380_sigat, spu_job_c61380_sig},
  {0x4c00, spu_job_c41a00, spu_job_c41a00_range, &spu_job_c41a00_sigat, spu_job_c41a00_sig},
  {0x4c00, spu_job_c27800, spu_job_c27800_range, &spu_job_c27800_sigat, spu_job_c27800_sig},
  {0x4c00, spu_job_c47380, spu_job_c47380_range, &spu_job_c47380_sigat, spu_job_c47380_sig},
  {0x4c00, spu_job_bfa000, spu_job_bfa000_range, &spu_job_bfa000_sigat, spu_job_bfa000_sig},
  {0x4c00, spu_job_c62580, spu_job_c62580_range, &spu_job_c62580_sigat, spu_job_c62580_sig},
  {0x4c00, spu_job_c91780, spu_job_c91780_range, &spu_job_c91780_sigat, spu_job_c91780_sig},
  {0x4c00, spu_job_cb0f00, spu_job_cb0f00_range, &spu_job_cb0f00_sigat, spu_job_cb0f00_sig},
  {0x1b400, spu_job_cb0f00_s1b400, spu_job_cb0f00_s1b400_range, &spu_job_cb0f00_s1b400_sigat, spu_job_cb0f00_s1b400_sig},
  {0x1d000, spu_job_cb0f00_s1d000, cb0f00_s1d000_range_clamped, &spu_job_cb0f00_s1d000_sigat, spu_job_cb0f00_s1d000_sig},
  {0x21400, spu_job_ca3480_b, spu_job_ca3480_b_range, &spu_job_ca3480_b_sigat, spu_job_ca3480_b_sig},
  {0, 0, 0, 0, 0},
  {0x22400, spu_job_ca3480_s22400, spu_job_ca3480_s22400_range, &spu_job_ca3480_s22400_sigat, spu_job_ca3480_s22400_sig},
  {0x7c00, spu_job_d1cd00_s7c00, spu_job_d1cd00_s7c00_range, &spu_job_d1cd00_s7c00_sigat, spu_job_d1cd00_s7c00_sig},
  {0x7c00, spu_job_d0da00_s7c00, spu_job_d0da00_s7c00_range, &spu_job_d0da00_s7c00_sigat, spu_job_d0da00_s7c00_sig},
  {0x1e400, spu_job_ca3480_s1e400, spu_job_ca3480_s1e400_range, &spu_job_ca3480_s1e400_sigat, spu_job_ca3480_s1e400_sig},
  {0x21800, spu_job_ca3480_s21800, spu_job_ca3480_s21800_range, &spu_job_ca3480_s21800_sigat, spu_job_ca3480_s21800_sig},
  {0x21c00, spu_job_ca3480_s21c00, spu_job_ca3480_s21c00_range, &spu_job_ca3480_s21c00_sigat, spu_job_ca3480_s21c00_sig},
  {0x22000, spu_job_ca3480_s22000, spu_job_ca3480_s22000_range, &spu_job_ca3480_s22000_sigat, spu_job_ca3480_s22000_sig},
  {0x24800, spu_job_ca3480_s24800, spu_job_ca3480_s24800_range, &spu_job_ca3480_s24800_sigat, spu_job_ca3480_s24800_sig},
  {0x16800, spu_job_c91780_s16800, spu_job_c91780_s16800_range, &spu_job_c91780_s16800_sigat, spu_job_c91780_s16800_sig},
  {0x16c00, spu_job_c91780_s16c00, spu_job_c91780_s16c00_range, &spu_job_c91780_s16c00_sigat, spu_job_c91780_s16c00_sig},
  {0x17000, spu_job_c91780_s17000, spu_job_c91780_s17000_range, &spu_job_c91780_s17000_sigat, spu_job_c91780_s17000_sig},
  {0x17400, spu_job_c91780_s17400, spu_job_c91780_s17400_range, &spu_job_c91780_s17400_sigat, spu_job_c91780_s17400_sig},
  {0x5c00, spu_job_c91780_s5c00, spu_job_c91780_s5c00_range, &spu_job_c91780_s5c00_sigat, spu_job_c91780_s5c00_sig},
  {0x16400, spu_job_c91780_s16400, spu_job_c91780_s16400_range, &spu_job_c91780_s16400_sigat, spu_job_c91780_s16400_sig},
  {0x8000, spu_run_jq_8000, spu_run_jq_8000_range, &spu_run_jq_8000_sigat, spu_run_jq_8000_sig},
  {0x5c00, spu_job_c8cb80_s5c00, spu_job_c8cb80_s5c00_range, &spu_job_c8cb80_s5c00_sigat, spu_job_c8cb80_s5c00_sig},
  {0x14000, spu_job_c91780_s14000, spu_job_c91780_s14000_range, &spu_job_c91780_s14000_sigat, spu_job_c91780_s14000_sig},
  {0x37600, spu_job_d1cd00_s37600, spu_job_d1cd00_s37600_range, &spu_job_d1cd00_s37600_sigat, spu_job_d1cd00_s37600_sig},
  {0x1e800, spu_job_ca3480_s1e800, spu_job_ca3480_s1e800_range, &spu_job_ca3480_s1e800_sigat, spu_job_ca3480_s1e800_sig},
  {0x15400, spu_job_c91780_s15400, spu_job_c91780_s15400_range, &spu_job_c91780_s15400_sigat, spu_job_c91780_s15400_sig},
  {0x24c00, spu_job_ca3480_s24c00, spu_job_ca3480_s24c00_range, &spu_job_ca3480_s24c00_sigat, spu_job_ca3480_s24c00_sig},
  {0x25000, spu_job_ca3480_s25000, spu_job_ca3480_s25000_range, &spu_job_ca3480_s25000_sigat, spu_job_ca3480_s25000_sig},
  {0x5c00, spu_job_cb0f00_s5c00, spu_job_cb0f00_s5c00_range, &spu_job_cb0f00_s5c00_sigat, spu_job_cb0f00_s5c00_sig},
  {0x17000, spu_job_cb0f00_s17000, spu_job_cb0f00_s17000_range, &spu_job_cb0f00_s17000_sigat, spu_job_cb0f00_s17000_sig},
  {0x16c00, spu_job_ca3480_s16c00, spu_job_ca3480_s16c00_range, &spu_job_ca3480_s16c00_sigat, spu_job_ca3480_s16c00_sig},
  {0x1ec00, spu_job_ca3480_s1ec00, spu_job_ca3480_s1ec00_range, &spu_job_ca3480_s1ec00_sigat, spu_job_ca3480_s1ec00_sig},
  {0x1f000, spu_job_ca3480_s1f000, spu_job_ca3480_s1f000_range, &spu_job_ca3480_s1f000_sigat, spu_job_ca3480_s1f000_sig},
  {0x1a800, spu_job_cb0f00_s1a800, spu_job_cb0f00_s1a800_range, &spu_job_cb0f00_s1a800_sigat, spu_job_cb0f00_s1a800_sig},
  {0x1cc00, spu_job_cb0f00_s1cc00, spu_job_cb0f00_s1cc00_range, &spu_job_cb0f00_s1cc00_sigat, spu_job_cb0f00_s1cc00_sig},
  {0x2c800, spu_job_c91780_s2c800, spu_job_c91780_s2c800_range, &spu_job_c91780_s2c800_sigat, spu_job_c91780_s2c800_sig},
  {0x2cc00, spu_job_c91780_s2cc00, spu_job_c91780_s2cc00_range, &spu_job_c91780_s2cc00_sigat, spu_job_c91780_s2cc00_sig},
};
const unsigned g_spu_nbodies = sizeof g_spu_bodies / sizeof g_spu_bodies[0];

const SpuJobGuest g_spu_job_guest[] = {
  {spu_job_c91780_s5c00, 0xc91780u},
  {spu_job_c91780_s16400, 0xc91780u},
  {spu_job_c91780_s16800, 0xc91780u},
  {spu_job_c91780_s16c00, 0xc91780u},
  {spu_job_c91780_s17000, 0xc91780u},
  {spu_job_c91780_s17400, 0xc91780u},
  {spu_job_d1cd00_s7c00, 0xd1cd00u},
  {spu_job_d0da00_s7c00, 0xd0da00u},
  {spu_job_ca3480_s1e400, 0xca3480u},
  {spu_job_ca3480_s21800, 0xca3480u},
  {spu_job_ca3480_s21c00, 0xca3480u},
  {spu_job_ca3480_s22000, 0xca3480u},
  {spu_job_ca3480_s24800, 0xca3480u},
  {spu_job_ca3480_s22400, 0xca3480u},
  {spu_job_c06a80, 0xc06a80u},
  {spu_job_d08180, 0xd08180u},
  {spu_job_c46680, 0xc46680u},
  {spu_job_c2aa00, 0xc2aa00u},
  {spu_job_c05d00, 0xc05d00u},
  {spu_job_c17780, 0xc17780u},
  {spu_job_c2cf80, 0xc2cf80u},
  {spu_job_c3f400, 0xc3f400u},
  {spu_job_c43c00, 0xc43c00u},
  {spu_job_c14a80, 0xc14a80u},
  {spu_job_beff00, 0xbeff00u},
  {spu_job_c1eb80, 0xc1eb80u},
  {spu_job_ca3480, 0xca3480u},
  {spu_job_cfcf80_c, 0xcfcf80u},
  {spu_job_c8cb80, 0xc8cb80u},
  {spu_job_c1b200, 0xc1b200u},
  {spu_job_c61380, 0xc61380u},
  {spu_job_c41a00, 0xc41a00u},
  {spu_job_c27800, 0xc27800u},
  {spu_job_c47380, 0xc47380u},
  {spu_job_bfa000, 0xbfa000u},
  {spu_job_c62580, 0xc62580u, 0x2200},
  {spu_job_c91780, 0xc91780u},
  {spu_job_cb0f00, 0xcb0f00u},
  {spu_job_cb0f00_s1b400, 0xcb0f00u},
  {spu_job_cb0f00_s1d000, 0xcb0f00u},
  {spu_job_c8cb80_s5c00, 0xc8cb80u},
  {spu_job_c91780_s14000, 0xc91780u},
  {spu_job_d1cd00_s37600, 0xd1cd00u},
  {spu_job_ca3480_s1e800, 0xca3480u},
  {spu_job_c91780_s15400, 0xc91780u},
  {spu_job_ca3480_s24c00, 0xca3480u},
  {spu_job_ca3480_s25000, 0xca3480u},
  {spu_job_cb0f00_s5c00, 0xcb0f00u},
  {spu_job_cb0f00_s17000, 0xcb0f00u},
  {spu_job_ca3480_s16c00, 0xca3480u},
  {spu_job_ca3480_s1ec00, 0xca3480u},
  {spu_job_ca3480_s1f000, 0xca3480u},
  {spu_job_cb0f00_s1a800, 0xcb0f00u},
  {spu_job_cb0f00_s1cc00, 0xcb0f00u},
  {spu_job_c91780_s2c800, 0xc91780u},
  {spu_job_c91780_s2cc00, 0xc91780u},
};
const unsigned g_spu_njob_guest = sizeof g_spu_job_guest / sizeof g_spu_job_guest[0];
