#pragma once
#include <stdint.h>

enum {
    SpvOpExtInstImport=11, SpvOpExtInst=12, SpvOpMemoryModel=14,
    SpvOpEntryPoint=15, SpvOpExecutionMode=16, SpvOpCapability=17,
    SpvOpTypeVoid=19, SpvOpTypeBool=20, SpvOpTypeInt=21, SpvOpTypeFloat=22,
    SpvOpTypeVector=23, SpvOpTypeImage=25, SpvOpTypeSampledImage=27,
    SpvOpTypeArray=28, SpvOpTypeStruct=30, SpvOpTypePointer=32,
    SpvOpTypeFunction=33,
    SpvOpConstantTrue=41, SpvOpConstantFalse=42, SpvOpConstant=43,
    SpvOpConstantComposite=44,
    SpvOpFunction=54, SpvOpFunctionEnd=56, SpvOpVariable=59,
    SpvOpLoad=61, SpvOpStore=62, SpvOpAccessChain=65,
    SpvOpDecorate=71, SpvOpMemberDecorate=72,
    SpvOpVectorShuffle=79, SpvOpCompositeConstruct=80,
    SpvOpCompositeExtract=81, SpvOpCompositeInsert=82,
    SpvOpImageSampleImplicitLod=87, SpvOpImageSampleExplicitLod=88,
    SpvOpImage=100, SpvOpImageQuerySizeLod=103,
    SpvOpConvertFToS=110, SpvOpConvertSToF=111, SpvOpQuantizeToF16=116,
    SpvOpBitcast=124,
    SpvOpFNegate=127, SpvOpIAdd=128, SpvOpFAdd=129, SpvOpFSub=131,
    SpvOpIMul=132, SpvOpFMul=133, SpvOpFDiv=136,
    SpvOpDot=148,
    SpvOpIsNan=156,
    SpvOpAny=154, SpvOpAll=155,
    SpvOpLogicalOr=166, SpvOpLogicalAnd=167, SpvOpLogicalNot=168,
    SpvOpSelect=169,
    SpvOpIEqual=170, SpvOpINotEqual=171,
    SpvOpSGreaterThanEqual=175, SpvOpSLessThan=177, SpvOpSLessThanEqual=179,
    SpvOpFOrdEqual=180, SpvOpFUnordNotEqual=183, SpvOpFOrdLessThan=184,
    SpvOpFOrdGreaterThan=186, SpvOpFOrdLessThanEqual=188,
    SpvOpFOrdGreaterThanEqual=190,
    SpvOpDPdx=207, SpvOpDPdy=208,
    SpvOpLoopMerge=246,
    SpvOpLabel=248, SpvOpBranch=249, SpvOpBranchConditional=250,
    SpvOpSelectionMerge=247,
    SpvOpKill=252, SpvOpReturn=253,
};
enum {
    GlslFAbs=4, GlslFSign=6, GlslFloor=8, GlslFract=10, GlslSin=13, GlslCos=14,
    GlslPow=26, GlslExp2=29, GlslLog2=30, GlslInverseSqrt=32, GlslFMin=37,
    GlslFMax=40, GlslFClamp=43, GlslFMix=46,
    GlslPackSnorm4x8=54, GlslPackUnorm4x8=55, GlslPackUnorm2x16=57,
    GlslPackHalf2x16=58, GlslUnpackUnorm2x16=61, GlslUnpackHalf2x16=62,
    GlslUnpackSnorm4x8=63, GlslUnpackUnorm4x8=64,
};
enum { SpvImgBias=0x1, SpvImgLod=0x2, SpvImgGrad=0x4 };
enum { SpvSCUniformConstant=0, SpvSCInput=1, SpvSCUniform=2, SpvSCOutput=3,
       SpvSCFunction=7, SpvSCPushConstant=9 };
enum { SpvDecBlock=2, SpvDecBufferBlock=3, SpvDecArrayStride=6, SpvDecBuiltIn=11,
       SpvDecLocation=30, SpvDecBinding=33, SpvDecDescriptorSet=34, SpvDecOffset=35 };
enum { SpvBIPosition=0, SpvBIPointSize=1, SpvBIFragCoord=15, SpvBIFragDepth=22,
       SpvBIFrontFacing=17, SpvBIPointCoord=16 };
enum { SpvEMVertex=0, SpvEMFragment=4 };
enum { SpvExecOriginUpperLeft=7, SpvExecDepthReplacing=12 };
enum { SpvCapImageQuery=50 };

#define SPVM_GLOB 32768
#define SPVM_DECO 8192
#define SPVM_BODY 131072
#define SPVM_CI_CACHE 1024

typedef struct {
    uint32_t glob[SPVM_GLOB]; int gn;
    uint32_t deco[SPVM_DECO]; int dn;
    uint32_t body[SPVM_BODY]; int bn;
    uint32_t next_id, glsl;
    int fail;
    uint32_t xcap[8]; int nxcap;
    uint32_t t_void, t_fnvoid, t_bool, t_f32, t_i32, t_u32;
    uint32_t t_vf[5];
    uint32_t t_bv4;
    struct { uint32_t sc, ty, id; } ptrs[64]; int nptr;
    struct { uint32_t bits, id; } cf[512]; int ncf;
    struct { int32_t v; uint32_t id; } ci[SPVM_CI_CACHE]; int nci;
    struct { uint32_t v, id; } cu[64]; int ncu;
} SpvMod;

void     spvm_init(SpvMod* m);
uint32_t spvm_id(SpvMod* m);
void     spvm_cap(SpvMod* m, uint32_t capability);
void spvm_g(SpvMod* m, uint16_t op, const uint32_t* a, int n);
void spvm_d(SpvMod* m, uint16_t op, const uint32_t* a, int n);
void spvm_b(SpvMod* m, uint16_t op, const uint32_t* a, int n);
uint32_t spvm_ptr(SpvMod* m, uint32_t sclass, uint32_t type);
uint32_t spvm_cf(SpvMod* m, float f);
uint32_t spvm_ci(SpvMod* m, int32_t v);
uint32_t spvm_cu(SpvMod* m, uint32_t v);
uint32_t spvm_cf4(SpvMod* m, float x, float y, float z, float w);
int spvm_finish(SpvMod* m, uint32_t entry, uint32_t exec_model,
                const uint32_t* iface, int niface, int depth_replacing,
                uint32_t* out, int cap);

uint32_t spvb_load(SpvMod* m, uint32_t type, uint32_t ptr);
void     spvb_store(SpvMod* m, uint32_t ptr, uint32_t val);
uint32_t spvb_bin(SpvMod* m, uint16_t op, uint32_t type, uint32_t a, uint32_t b);
uint32_t spvb_un(SpvMod* m, uint16_t op, uint32_t type, uint32_t a);
uint32_t spvb_ext1(SpvMod* m, uint32_t type, uint32_t inst, uint32_t a);
uint32_t spvb_ext2(SpvMod* m, uint32_t type, uint32_t inst, uint32_t a, uint32_t b);
uint32_t spvb_ext3(SpvMod* m, uint32_t type, uint32_t inst, uint32_t a, uint32_t b, uint32_t c);
uint32_t spvb_shuffle4(SpvMod* m, uint32_t v, const uint8_t swz[4]);
uint32_t spvb_extract(SpvMod* m, uint32_t type, uint32_t v, uint32_t idx);
uint32_t spvb_construct4(SpvMod* m, uint32_t x, uint32_t y, uint32_t z, uint32_t w);
uint32_t spvb_splat4(SpvMod* m, uint32_t f);
uint32_t spvb_select4(SpvMod* m, uint32_t bvec, uint32_t a, uint32_t b);
