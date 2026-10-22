#include "vk_draw.h"
#include <vulkan/vulkan.h>
#include "vk_present.h"
#include "gcm_state.h"
#include "vp_spirv.h"
#include "fp_spirv.h"
#include "fp_decode.h"
#include "tex_decode.h"
#include "capture.h"
#include "statecap.h"
int dbg_flat_fs(uint32_t*,int);
int dbg_uv_fs(uint32_t*,int);
int dbg_tex_fs(uint32_t*,int);
int dbg_passthru_vs(uint32_t*,int);
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

enum { DP_FP, DP_KEY, DP_BUILD, DP_TEX, DP_IDX, DP_VFETCH, DP_UBO, DP_DESC,
       DP_REC, DP_HASH, DP_CLEAR, DP_XFER, DP_FLIP, DP_N };
static const char* const g_dpname[DP_N]={"fp","key","build","tex","idx",
                                         "vfetch","ubo","desc","rec","hash",
                                         "clear","xfer","flip"};
static uint64_t g_dpacc[DP_N];
static uint64_t g_dpdraws, g_dpverts, g_dptris, g_dptexdec, g_dppipenew,
                g_dppipeevict;
static uint64_t g_dpvpcskip, g_dpdsethit, g_dpfpmemo, g_dpi16;
static uint64_t g_dpvbytes, g_dpvbytes16;
static int g_dpfpstruct;
static uint32_t g_dpvhi, g_dpihi, g_dpuhi, g_dpthi;
static int g_dprof=-1;
static int dprof_on(void){
    if(g_dprof<0) g_dprof=(getenv("PS3_RSX_DRAWPROF")||getenv("PS3_BENCH"))?1:0;
    return g_dprof;
}
static uint64_t dp_now(void){
    LARGE_INTEGER q; QueryPerformanceCounter(&q); return (uint64_t)q.QuadPart;
}
#define DP_T0(v)      uint64_t v = dprof_on() ? dp_now() : 0
#define DP_T1(slot,v) do{ if(dprof_on()) g_dpacc[slot] += dp_now()-(v); }while(0)

static uint8_t*  g_base;
static uint32_t  g_local_ea, g_local_size;
static uint64_t  g_mem_size;
static uint32_t (*g_ioff2ea)(uint32_t);
int g_shot_req;

static VkDevice g_dev; static VkPhysicalDevice g_phys; static VkQueue g_q;
static VkCommandPool g_pool; static VkCommandBuffer g_cmd;
static VkFence g_fence;
#define NCMD 8
static VkCommandBuffer g_cmds[NCMD]; static VkFence g_fences[NCMD];
static int g_cmdi, g_inflight[NCMD];
static uint64_t g_cmd_seq[NCMD], g_cmd_nsub;
#define NFRAME 2
static int g_fslot;
static int g_frame_last_cmd[2]={-1,-1};
static uint64_t g_frame_last_seq[2];
static VkPipeline g_pipe_dead[2][128]; static int g_ndead[2];
static uint32_t g_vend, g_iend, g_uend, g_tend;
static int g_tstaged;
static int g_tstage_slot=-1; static uint64_t g_tstage_seq;
#define NQUERY 512
static VkQueryPool g_qpool;
static int g_up=0;
static int rsxd_diag_on(const char* on, const char* off){
    if(getenv(off)) return 0;
    return (getenv(on) || getenv("PS3_RSX_DIAG")) ? 1 : 0;
}
static int g_in_rp=0;
static VkRenderPass g_rp;
static VkRenderPass g_rpf;
static VkDescriptorSetLayout g_dsl;
static VkPipelineLayout g_playout;
static VkDescriptorPool g_dpool;
static VkDescriptorPool g_dpools[2];
static VkSampler g_sampler;
static VkSampler g_vsampler;
static VkImage g_white; static VkDeviceMemory g_white_mem; static VkImageView g_white_view;
static VkImage g_white_c, g_white_3d;
static VkDeviceMemory g_white_c_mem, g_white_3d_mem;
static VkImageView g_white_view_c, g_white_view_3d;
static VkImageView white_view_for(int type){
    return type==FP_TEX_CUBE ? g_white_view_c
         : type==FP_TEX_3D   ? g_white_view_3d
                             : g_white_view;
}

#define VBUF_CAP (192u<<20)
#define IBUF_CAP (32u<<20)
#define UBUF_CAP (32u<<20)
static VkBuffer g_vbuf, g_ibuf, g_ubuf;
static VkDeviceMemory g_vmem, g_imem, g_umem;
static uint8_t *g_vptr, *g_iptr, *g_uptr;
static uint32_t g_voff, g_ioff, g_uoff;
static uint32_t g_ubo_align=256;
static uint32_t g_vpc_uoff, g_vpc_epoch;
static int      g_vpc_valid;
#define PTBUF_CAP ((4u*544u+16u)*16u)
static VkBuffer g_ptbuf; static VkDeviceMemory g_ptmem; static uint8_t* g_ptptr;

typedef struct {
    uint32_t ea, w, h;
    VkImage img; VkDeviceMemory mem; VkImageView view;
    VkImage z;   VkDeviceMemory zmem; VkImageView zview;
    uint32_t zea, zpitch;
    VkFramebuffer fb;
    int isf;
    int inited;
    int layout;
    uint64_t last_frame;
    int zfloat;
    int hnext;
} Surf;
#define NSURF 96
static Surf g_surf[NSURF];
static uint64_t g_frame;
#define NSURFH 256
static int g_surfhead[NSURFH];
static uint32_t surf_hkey(uint32_t ea){
    uint32_t h=ea*2654435761u; return (h^(h>>15))&(NSURFH-1);
}
static void surf_unlink(Surf* s){
    int* p=&g_surfhead[surf_hkey(s->ea)];
    while(*p){ Surf* c=&g_surf[*p-1];
        if(c==s){ *p=c->hnext; c->hnext=0; return; }
        p=&c->hnext; }
}
static void surf_link(Surf* s){
    uint32_t b=surf_hkey(s->ea);
    s->hnext=g_surfhead[b];
    g_surfhead[b]=(int)(s-g_surf)+1;
}

typedef struct { uint64_t key, last_use; VkPipeline pipe;
                 uint32_t used_attrs, tex_used, vtex_used, nconst; int next; } Pipe;
#define NPIPE     8192
#define NPIPEBUCK 16384
static Pipe g_pipe[NPIPE]; static int g_npipe;
static int g_pipe_head[NPIPEBUCK];
static uint64_t g_pipe_clock;
static VkPipeline g_pipe_retired[128]; static int g_nretired;

typedef struct {
    uint32_t ea, fmt, rect, ctl3, qhash;
    VkImage img; VkDeviceMemory mem; VkImageView view;
    uint64_t last_frame, use_frame;
    uint64_t use_drain;
    int ready;
    uint32_t nmip;
    uint8_t  type;
    uint32_t depth;
    uint64_t bytes;
    int      hnext;
} Tex;
#define NTEX 1024
static Tex g_tex[NTEX];
#define NTEXHASH 2048
static int g_texhead[NTEXHASH];
static uint64_t g_tex_drain;
#define TBUF_CAP (64u<<20)
static VkBuffer g_tbuf; static VkDeviceMemory g_tmem; static uint8_t* g_tptr;
static uint32_t g_toff;

#define WBUF_CAP  (2u<<20)
#define WB_SLOTS  2
#define WB_MAX    32
typedef struct { uint32_t ea, w, h, off; int isf; } WbEnt;
static VkBuffer g_wbuf[WB_SLOTS]; static VkDeviceMemory g_wbmem[WB_SLOTS];
static uint8_t* g_wbptr[WB_SLOTS];
static WbEnt    g_wbent[WB_SLOTS][WB_MAX];
static int      g_wbn[WB_SLOTS];
static int      g_wbcmd[WB_SLOTS];
static uint64_t g_wbseq[WB_SLOTS];
static int      g_wbslot;
static uint32_t* g_texscratch;
typedef struct { uint64_t key; VkSampler s; } Samp;
#define NSAMP  128
#define NSAMPH 256
static Samp g_samp[NSAMP]; static int g_nsamp;
static int g_samph[NSAMPH];
static uint32_t samp_hslot(uint64_t k){
    uint64_t h=k*0x9e3779b97f4a7c15ull;
    return (uint32_t)(h>>40)&(NSAMPH-1);
}

#define NDSET 2048
typedef struct { uint64_t key; VkDescriptorSet set; uint32_t gen; } DsetEnt;
static DsetEnt  g_dset[NDSET];
static uint32_t g_dset_gen=1;
static int      g_dset_live;
static void dset_cache_drop(void){ g_dset_gen++; g_dset_live=0; }

static uint32_t g_prim;
typedef struct { uint32_t first, count; } Range;
static Range g_arr[256]; static int g_narr;
static Range g_idx[4096]; static int g_nidx;
static uint32_t g_inline[65536]; static uint32_t g_ninline;

extern RsxState g_rsx;

static uint64_t fnv1a(const void* p, size_t n, uint64_t h){
    const uint8_t* b=p;
    for(size_t i=0;i<n;i++){ h^=b[i]; h*=0x100000001b3ull; }
    return h;
}
static uint64_t hash_u32s(const uint32_t* p, size_t n, uint64_t h){
    for(size_t i=0;i<n;i++){ h=(h^p[i])*0xff51afd7ed558ccdull; h^=h>>29; }
    return h;
}
static uint32_t f2u(float f){ uint32_t u; memcpy(&u,&f,4); return u; }
static void write_bmp(const char* path, const void* bgra, uint32_t w, uint32_t h){
    FILE* f=fopen(path,"wb");
    if(!f) return;
    uint32_t isz=w*h*4, fsz=54+isz, offb=54, bi=40;
    uint8_t hdr[54]={'B','M'};
    memcpy(hdr+2,&fsz,4); memcpy(hdr+10,&offb,4); memcpy(hdr+14,&bi,4);
    memcpy(hdr+18,&w,4);
    int32_t hneg=-(int32_t)h; memcpy(hdr+22,&hneg,4);
    uint16_t pl=1,bpp=32; memcpy(hdr+26,&pl,2); memcpy(hdr+28,&bpp,2);
    memcpy(hdr+34,&isz,4);
    fwrite(hdr,1,54,f); fwrite(bgra,1,isz,f);
    fclose(f);
}
static float zbias_scale(void){
    static float s=-1.0f;
    if(s<0.0f){ const char* e=getenv("PS3_RSX_ZBIAS"); s=e?(float)atof(e):1.0f; }
    return s;
}
static uint32_t rd32(uint32_t ea){
    const uint8_t* p=g_base+ea;
    return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];
}
static uint32_t resolve(uint32_t off, uint32_t location){
    if(location==GCM_LOCATION_MAIN) return g_ioff2ea?g_ioff2ea(off):0;
    if(off<g_local_size) return g_local_ea+off;
    return 0;
}
static uint32_t tex_zfunc(uint32_t unit){
    const RsxTexture* t=&g_rsx.tex[unit&15];
    uint32_t bf=(t->format>>8)&0x9f;
    if(bf<0x90||bf>0x93) return 0;
    uint32_t z=(t->address>>28)&0xf;
    { static uint32_t seen; if(!(seen>>unit&1)){ seen|=1u<<unit;
        uint32_t mag=(t->filter>>24)&0xf, min=(t->filter>>16)&0xf;
        fprintf(stderr,"[RSXD] depth texture u%u fmt=0x%02x address=0x%08x "
                "zfunc=%u (%s) filter min=%u mag=%u -> %s border=0x%08x\n",
                unit,(t->format>>8)&0xff,t->address,z,
                z?"hardware compare":"no compare - sampling depth",min,mag,
                (mag==2||min==2||min==4||min==6)?"4-tap PCF":"single compare",
                t->border_color); } }
    return z?z+1:0;
}
static int tex_filter_linear(uint32_t unit){
    uint32_t f=g_rsx.tex[unit&15].filter;
    uint32_t mag=(f>>24)&0xf, min=(f>>16)&0xf;
    return mag==2||min==2||min==4||min==6;
}
static int tex_target(uint32_t unit){
    uint32_t f=g_rsx.tex[unit&15].format;
    if((f>>2)&1) return FP_TEX_CUBE;
    return (((f>>4)&0xf)==3) ? FP_TEX_3D : FP_TEX_2D;
}
static uint32_t dma_loc(uint32_t handle){
    if((handle&~1u)==0xFEED0000u) return handle&1u;
    return GCM_LOCATION_LOCAL;
}

void rsxd_init(uint8_t* base, uint32_t local_ea, uint32_t local_size,
               uint32_t (*ioff2ea)(uint32_t), uint64_t mem_size){
    g_base=base; g_local_ea=local_ea; g_local_size=local_size; g_ioff2ea=ioff2ea;
    g_mem_size=mem_size;
}

static const uint8_t* guest_limit(uint32_t ea, uint32_t location){
    if(location==GCM_LOCATION_LOCAL&&
       ea>=g_local_ea&&(uint64_t)ea<(uint64_t)g_local_ea+g_local_size)
        return g_base+(uint64_t)g_local_ea+g_local_size;
    return g_base+g_mem_size;
}

static const VkPhysicalDeviceMemoryProperties* mem_props(void){
    static VkPhysicalDeviceMemoryProperties mp; static int got;
    if(!got){ vkGetPhysicalDeviceMemoryProperties(g_phys,&mp); got=1; }
    return &mp;
}
static uint32_t mem_type(uint32_t bits, VkMemoryPropertyFlags want){
    const VkPhysicalDeviceMemoryProperties* mp=mem_props();
    for(uint32_t i=0;i<mp->memoryTypeCount;i++)
        if((bits&(1u<<i))&&(mp->memoryTypes[i].propertyFlags&want)==want) return i;
    return UINT32_MAX;
}
static int make_buf(VkDeviceSize sz, VkBufferUsageFlags use,
                    VkBuffer* buf, VkDeviceMemory* mem, uint8_t** ptr){
    VkBufferCreateInfo bci={.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .size=sz,.usage=use,.sharingMode=VK_SHARING_MODE_EXCLUSIVE};
    if(vkCreateBuffer(g_dev,&bci,NULL,buf)) return 0;
    VkMemoryRequirements mr; vkGetBufferMemoryRequirements(g_dev,*buf,&mr);
    uint32_t mt=mem_type(mr.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if(mt==UINT32_MAX) return 0;
    VkMemoryAllocateInfo mai={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize=mr.size,.memoryTypeIndex=mt};
    if(vkAllocateMemory(g_dev,&mai,NULL,mem)) return 0;
    if(vkBindBufferMemory(g_dev,*buf,*mem,0)) return 0;
    if(vkMapMemory(g_dev,*mem,0,VK_WHOLE_SIZE,0,(void**)ptr)) return 0;
    return 1;
}

static VkPipelineStageFlags stages_for(VkAccessFlags a, int is_src){
    VkPipelineStageFlags s=0;
    if(a&(VK_ACCESS_COLOR_ATTACHMENT_READ_BIT|VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT))
        s|=VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    if(a&(VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT|
          VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT))
        s|=VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT|
           VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT;
    if(a&(VK_ACCESS_TRANSFER_READ_BIT|VK_ACCESS_TRANSFER_WRITE_BIT))
        s|=VK_PIPELINE_STAGE_TRANSFER_BIT;
    if(a&VK_ACCESS_SHADER_READ_BIT)
        s|=VK_PIPELINE_STAGE_VERTEX_SHADER_BIT|VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT;
    if(a&(VK_ACCESS_MEMORY_READ_BIT|VK_ACCESS_MEMORY_WRITE_BIT))
        s|=VK_PIPELINE_STAGE_ALL_COMMANDS_BIT;
    if(!s) s=is_src?VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT
                   :VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT;
    return s;
}

static int make_img_tex(uint32_t w, uint32_t h, uint32_t d, uint32_t nmip,
                        int type, VkFormat fmt, VkImage* img,
                        VkDeviceMemory* mem, VkImageView* view);

static void img_barrier1(VkImage img, VkImageAspectFlags aspect,
                         uint32_t nmip, uint32_t nlayer,
                         VkImageLayout from, VkImageLayout to,
                         VkAccessFlags src, VkAccessFlags dst){
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=src,.dstAccessMask=dst,.oldLayout=from,.newLayout=to,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=img,.subresourceRange={aspect,0,nmip,0,nlayer}};
    vkCmdPipelineBarrier(g_cmd,stages_for(src,1),stages_for(dst,0),
                         0,0,0,0,0,1,&b);
}

static int draw_up(void){
    if(g_up) return g_up>0;
    if(!rsxvk_init()){ g_up=-1; return 0; }
    g_up=-1;
    g_dev=rsxvk_device(); g_phys=rsxvk_phys(); g_q=rsxvk_queue();
    VkPhysicalDeviceProperties pp; vkGetPhysicalDeviceProperties(g_phys,&pp);
    g_ubo_align=(uint32_t)pp.limits.minUniformBufferOffsetAlignment;
    if(g_ubo_align<16) g_ubo_align=16;

    VkCommandPoolCreateInfo cpci={.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        .queueFamilyIndex=rsxvk_qfam()};
    if(vkCreateCommandPool(g_dev,&cpci,NULL,&g_pool)) return 0;
    VkCommandBufferAllocateInfo cbai={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool=g_pool,.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,.commandBufferCount=NCMD};
    if(vkAllocateCommandBuffers(g_dev,&cbai,g_cmds)) return 0;
    VkFenceCreateInfo fci={.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    for(int i=0;i<NCMD;i++)
        if(vkCreateFence(g_dev,&fci,NULL,&g_fences[i])) return 0;
    g_cmdi=0; g_cmd=g_cmds[0]; g_fence=g_fences[0];
    { VkQueryPoolCreateInfo qpi={.sType=VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO,
        .queryType=VK_QUERY_TYPE_OCCLUSION,.queryCount=NQUERY};
      if(vkCreateQueryPool(g_dev,&qpi,NULL,&g_qpool)) g_qpool=VK_NULL_HANDLE; }

    VkAttachmentDescription at[2]={
        {.format=VK_FORMAT_B8G8R8A8_UNORM,.samples=1,
         .loadOp=VK_ATTACHMENT_LOAD_OP_LOAD,.storeOp=VK_ATTACHMENT_STORE_OP_STORE,
         .stencilLoadOp=VK_ATTACHMENT_LOAD_OP_DONT_CARE,
         .stencilStoreOp=VK_ATTACHMENT_STORE_OP_DONT_CARE,
         .initialLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
         .finalLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL},
        {.format=VK_FORMAT_D32_SFLOAT,.samples=1,
         .loadOp=VK_ATTACHMENT_LOAD_OP_LOAD,.storeOp=VK_ATTACHMENT_STORE_OP_STORE,
         .stencilLoadOp=VK_ATTACHMENT_LOAD_OP_DONT_CARE,
         .stencilStoreOp=VK_ATTACHMENT_STORE_OP_DONT_CARE,
         .initialLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
         .finalLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL}};
    VkAttachmentReference cref={0,VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkAttachmentReference zref={1,VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL};
    VkSubpassDescription sp={.pipelineBindPoint=VK_PIPELINE_BIND_POINT_GRAPHICS,
        .colorAttachmentCount=1,.pColorAttachments=&cref,
        .pDepthStencilAttachment=&zref};
    VkRenderPassCreateInfo rpci={.sType=VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO,
        .attachmentCount=2,.pAttachments=at,.subpassCount=1,.pSubpasses=&sp};
    if(vkCreateRenderPass(g_dev,&rpci,NULL,&g_rp)) return 0;
    at[0].format=VK_FORMAT_R32G32B32A32_SFLOAT;
    if(vkCreateRenderPass(g_dev,&rpci,NULL,&g_rpf)) return 0;
    at[0].format=VK_FORMAT_B8G8R8A8_UNORM;

    VkDescriptorSetLayoutBinding binds[23];
    binds[0]=(VkDescriptorSetLayoutBinding){.binding=0,
        .descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,
        .descriptorCount=1,.stageFlags=VK_SHADER_STAGE_VERTEX_BIT};
    binds[1]=(VkDescriptorSetLayoutBinding){.binding=1,
        .descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,
        .descriptorCount=1,.stageFlags=VK_SHADER_STAGE_FRAGMENT_BIT};
    for(int i=0;i<4;i++)
        binds[2+i]=(VkDescriptorSetLayoutBinding){.binding=4u+(uint32_t)i,
            .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,
            .descriptorCount=1,.stageFlags=VK_SHADER_STAGE_VERTEX_BIT};
    for(int i=0;i<16;i++)
        binds[6+i]=(VkDescriptorSetLayoutBinding){.binding=8u+(uint32_t)i,
            .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,
            .descriptorCount=1,.stageFlags=VK_SHADER_STAGE_FRAGMENT_BIT};
    binds[22]=(VkDescriptorSetLayoutBinding){.binding=24,
        .descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
        .descriptorCount=1,.stageFlags=VK_SHADER_STAGE_FRAGMENT_BIT};
    VkDescriptorSetLayoutCreateInfo dslci={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
        .bindingCount=23,.pBindings=binds};
    if(vkCreateDescriptorSetLayout(g_dev,&dslci,NULL,&g_dsl)) return 0;
    VkPipelineLayoutCreateInfo plci={.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
        .setLayoutCount=1,.pSetLayouts=&g_dsl};
    if(vkCreatePipelineLayout(g_dev,&plci,NULL,&g_playout)) return 0;
    VkDescriptorPoolSize psz[3]={
        {VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,8192*2},
        {VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,8192*20},
        {VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,8192}};
    VkDescriptorPoolCreateInfo dpci={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
        .maxSets=8192,.poolSizeCount=3,.pPoolSizes=psz};
    for(int i=0;i<NFRAME;i++)
        if(vkCreateDescriptorPool(g_dev,&dpci,NULL,&g_dpools[i])) return 0;
    g_dpool=g_dpools[0];
    VkSamplerCreateInfo sci={.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO,
        .magFilter=VK_FILTER_LINEAR,.minFilter=VK_FILTER_LINEAR,
        .mipmapMode=VK_SAMPLER_MIPMAP_MODE_LINEAR,
        .addressModeU=VK_SAMPLER_ADDRESS_MODE_REPEAT,
        .addressModeV=VK_SAMPLER_ADDRESS_MODE_REPEAT,
        .addressModeW=VK_SAMPLER_ADDRESS_MODE_REPEAT,
        .maxLod=VK_LOD_CLAMP_NONE};
    if(vkCreateSampler(g_dev,&sci,NULL,&g_sampler)) return 0;
    if(!getenv("PS3_RSX_VTEXLINEAR")){
        VkSamplerCreateInfo vsci={.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO,
            .magFilter=VK_FILTER_NEAREST,.minFilter=VK_FILTER_NEAREST,
            .mipmapMode=VK_SAMPLER_MIPMAP_MODE_NEAREST,
            .addressModeU=VK_SAMPLER_ADDRESS_MODE_REPEAT,
            .addressModeV=VK_SAMPLER_ADDRESS_MODE_REPEAT,
            .addressModeW=VK_SAMPLER_ADDRESS_MODE_REPEAT,
            .maxLod=0.f};
        if(vkCreateSampler(g_dev,&vsci,NULL,&g_vsampler)) return 0;
    } else g_vsampler=g_sampler;

    if(!make_buf(VBUF_CAP,VK_BUFFER_USAGE_VERTEX_BUFFER_BIT,&g_vbuf,&g_vmem,&g_vptr)) return 0;
    if(!make_buf(IBUF_CAP,VK_BUFFER_USAGE_INDEX_BUFFER_BIT,&g_ibuf,&g_imem,&g_iptr)) return 0;
    if(!make_buf(UBUF_CAP,VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT,&g_ubuf,&g_umem,&g_uptr)) return 0;
    g_voff=0; g_vend=VBUF_CAP/NFRAME;
    g_ioff=0; g_iend=IBUF_CAP/NFRAME;
    g_uoff=0; g_uend=UBUF_CAP/NFRAME;
    g_toff=0; g_tend=TBUF_CAP;
    if(!make_buf(TBUF_CAP,VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
                          VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                 &g_tbuf,&g_tmem,&g_tptr)) return 0;
    for(int i=0;i<WB_SLOTS;i++){
        if(!make_buf(WBUF_CAP,VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                     &g_wbuf[i],&g_wbmem[i],&g_wbptr[i])) return 0;
        g_wbcmd[i]=-1; g_wbn[i]=0;
    }
    g_texscratch=malloc((size_t)4096*4096*4);
    if(!g_texscratch) return 0;
    if(getenv("PS3_RSX_PIXTRACE")){
        if(!make_buf(PTBUF_CAP,VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                     &g_ptbuf,&g_ptmem,&g_ptptr)) return 0;
        memset(g_ptptr,0,PTBUF_CAP);
    }

    VkImageCreateInfo ici={.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .imageType=VK_IMAGE_TYPE_2D,.format=VK_FORMAT_B8G8R8A8_UNORM,
        .extent={1,1,1},.mipLevels=1,.arrayLayers=1,.samples=1,
        .tiling=VK_IMAGE_TILING_OPTIMAL,
        .usage=VK_IMAGE_USAGE_SAMPLED_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .initialLayout=VK_IMAGE_LAYOUT_UNDEFINED};
    if(vkCreateImage(g_dev,&ici,NULL,&g_white)) return 0;
    VkMemoryRequirements mr; vkGetImageMemoryRequirements(g_dev,g_white,&mr);
    uint32_t wmt=mem_type(mr.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if(wmt==UINT32_MAX) return 0;
    VkMemoryAllocateInfo mai={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize=mr.size,.memoryTypeIndex=wmt};
    if(vkAllocateMemory(g_dev,&mai,NULL,&g_white_mem)) return 0;
    if(vkBindImageMemory(g_dev,g_white,g_white_mem,0)) return 0;
    { VkCommandBufferBeginInfo bi={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
          .flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
      vkBeginCommandBuffer(g_cmd,&bi);
      VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
          .dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
          .oldLayout=VK_IMAGE_LAYOUT_UNDEFINED,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
          .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
          .image=g_white,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
      vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
      VkClearColorValue white={{1,1,1,1}};
      VkImageSubresourceRange rng={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
      vkCmdClearColorImage(g_cmd,g_white,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&white,1,&rng);
      b.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT; b.dstAccessMask=VK_ACCESS_SHADER_READ_BIT;
      b.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
      b.newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
      vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
      vkEndCommandBuffer(g_cmd);
      VkSubmitInfo si={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
          .commandBufferCount=1,.pCommandBuffers=&g_cmd};
      vkQueueSubmit(g_q,1,&si,g_fence);
      vkWaitForFences(g_dev,1,&g_fence,VK_TRUE,UINT64_MAX);
      vkResetFences(g_dev,1,&g_fence); }
    VkImageViewCreateInfo vci={.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
        .image=g_white,.viewType=VK_IMAGE_VIEW_TYPE_2D,.format=VK_FORMAT_B8G8R8A8_UNORM,
        .subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    if(vkCreateImageView(g_dev,&vci,NULL,&g_white_view)) return 0;

    { static const int types[2]={FP_TEX_CUBE,FP_TEX_3D};
      VkImage* imgs[2]={&g_white_c,&g_white_3d};
      VkDeviceMemory* mems[2]={&g_white_c_mem,&g_white_3d_mem};
      VkImageView* views[2]={&g_white_view_c,&g_white_view_3d};
      for(int k=0;k<2;k++){
        if(!make_img_tex(1,1,1,1,types[k],VK_FORMAT_B8G8R8A8_UNORM,
                         imgs[k],mems[k],views[k])) return 0;
        uint32_t layers=(types[k]==FP_TEX_CUBE)?6u:1u;
        VkCommandBufferBeginInfo bi2={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
            .flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
        vkBeginCommandBuffer(g_cmd,&bi2);
        VkImageMemoryBarrier wb={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
            .dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
            .oldLayout=VK_IMAGE_LAYOUT_UNDEFINED,
            .newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
            .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
            .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
            .image=*imgs[k],
            .subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,layers}};
        vkCmdPipelineBarrier(g_cmd,stages_for(wb.srcAccessMask,1),
              stages_for(wb.dstAccessMask,0),0,0,0,0,0,1,&wb);
        VkClearColorValue wc={{1,1,1,1}};
        VkImageSubresourceRange wr2={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,layers};
        vkCmdClearColorImage(g_cmd,*imgs[k],
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&wc,1,&wr2);
        wb.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
        wb.dstAccessMask=VK_ACCESS_SHADER_READ_BIT;
        wb.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        wb.newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
        vkCmdPipelineBarrier(g_cmd,stages_for(wb.srcAccessMask,1),
              stages_for(wb.dstAccessMask,0),0,0,0,0,0,1,&wb);
        vkEndCommandBuffer(g_cmd);
        VkSubmitInfo si2={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
            .commandBufferCount=1,.pCommandBuffers=&g_cmd};
        vkQueueSubmit(g_q,1,&si2,g_fence);
        vkWaitForFences(g_dev,1,&g_fence,VK_TRUE,UINT64_MAX);
        vkResetFences(g_dev,1,&g_fence);
      } }

    g_up=1;
    fprintf(stderr,"[RSXD] draw path up\n");
    return 1;
}

static int g_cmd_open=0;
static Surf* g_cur=0;

static int g_nq;
static struct { uint32_t ea, zea, nf, nv, zmask, zfunc, serial; } g_qinfo[NQUERY];
static int qprobe_on(void){
    static int on=-1;
    if(on<0) on=getenv("PS3_RSX_QPROBE")?1:0;
    return on&&g_qpool;
}
static void qprobe_flush(void){
    if(!qprobe_on()||!g_nq) return;
    static uint64_t res[NQUERY];
    if(vkGetQueryPoolResults(g_dev,g_qpool,0,(uint32_t)g_nq,sizeof res,res,
                             sizeof res[0],
                             VK_QUERY_RESULT_64_BIT|VK_QUERY_RESULT_WAIT_BIT)==VK_SUCCESS){
        for(int i=0;i<g_nq;i++)
            fprintf(stderr,"[QPROBE] #%u draw rt=0x%x zea=0x%x nf=%u nv=%u "
                    "zmask=%u zfunc=0x%x -> samples=%llu%s\n",
                    g_qinfo[i].serial,g_qinfo[i].ea,g_qinfo[i].zea,
                    g_qinfo[i].nf,g_qinfo[i].nv,g_qinfo[i].zmask,
                    g_qinfo[i].zfunc,(unsigned long long)res[i],
                    (res[i]&&!g_qinfo[i].zmask)
                      ? "   <-- PASSED THE TEST BUT DEPTH WRITES ARE MASKED OFF"
                      : (res[i]?"":"   (nothing passed)"));
    }
    g_nq=0;
}

static void cmd_retire(int i){
    if(!g_inflight[i]) return;
    vkWaitForFences(g_dev,1,&g_fences[i],VK_TRUE,UINT64_MAX);
    vkResetFences(g_dev,1,&g_fences[i]);
    vkResetCommandBuffer(g_cmds[i],0);
    g_inflight[i]=0;
}
static void cmd_begin(void){
    if(g_cmd_open) return;
    g_cmdi=(g_cmdi+1)%NCMD;
    cmd_retire(g_cmdi);
    g_cmd=g_cmds[g_cmdi]; g_fence=g_fences[g_cmdi];
    VkCommandBufferBeginInfo bi={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
    vkBeginCommandBuffer(g_cmd,&bi);
    g_cmd_open=1;
    if(qprobe_on()){ vkCmdResetQueryPool(g_cmd,g_qpool,0,NQUERY); g_nq=0; }
}
static void rp_end(void){
    if(g_in_rp){ vkCmdEndRenderPass(g_cmd); g_in_rp=0; }
}
static uint64_t g_dpsubmit_ticks; static uint64_t g_dpsubmits;
static uint64_t g_dpflip_wb, g_dpflip_present, g_dpflip_retire;
static void cmd_submit_ex(int wait){
    rp_end();
    if(!g_cmd_open) return;
    uint64_t t_sub=dprof_on()?dp_now():0;
    if(t_sub) g_dpsubmits++;
    vkEndCommandBuffer(g_cmd);
    VkSubmitInfo si={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount=1,.pCommandBuffers=&g_cmd};
    vkQueueSubmit(g_q,1,&si,g_fences[g_cmdi]);
    g_inflight[g_cmdi]=1; g_cmd_seq[g_cmdi]=++g_cmd_nsub;
    g_cmd_open=0; g_cur=0;
    if(wait){
        cmd_retire(g_cmdi);
        qprobe_flush();
    }
    rsxvk_pump_tick();
    if(t_sub) g_dpsubmit_ticks+=dp_now()-t_sub;
}
static void cmd_submit(void){ cmd_submit_ex(1); }
static void cmd_flush(void){  cmd_submit_ex(0); }
static void cmd_retire_seq(int slot, uint64_t seq){
    if(slot>=0&&g_inflight[slot]&&g_cmd_seq[slot]==seq) cmd_retire(slot);
}
static void tstage_settle(void){
    if(g_tstage_slot<0) return;
    cmd_retire_seq(g_tstage_slot,g_tstage_seq);
    g_tstage_slot=-1;
}

static void wb_drain(int slot, int dump){
    if(!g_wbn[slot] || g_wbcmd[slot] < 0){ g_wbn[slot]=0; g_wbcmd[slot]=-1; return; }
    cmd_retire_seq(g_wbcmd[slot],g_wbseq[slot]);
    for(int k=0;k<g_wbn[slot];k++){
        const WbEnt* e=&g_wbent[slot][k];
        if(!e->isf){
            const uint8_t* sp3=g_wbptr[slot]+e->off;
            for(uint32_t y=0;y<e->h;y++) for(uint32_t x=0;x<e->w;x++){
                const uint8_t* s3=sp3+(size_t)(y*e->w+x)*4;
                uint8_t* d=g_base+e->ea+(size_t)(y*e->w+x)*4;
                d[0]=s3[3]; d[1]=s3[2]; d[2]=s3[1]; d[3]=s3[0];
            }
            continue;
        }
        const float* fp2=(const float*)(g_wbptr[slot]+e->off);
        for(uint32_t y=0;y<e->h;y++) for(uint32_t x=0;x<e->w;x++){
            uint32_t bits; memcpy(&bits,&fp2[(y*e->w+x)*4],4);
            uint8_t* d=g_base+e->ea+(y*e->w+x)*4;
            d[0]=(uint8_t)(bits>>24); d[1]=(uint8_t)(bits>>16);
            d[2]=(uint8_t)(bits>>8);  d[3]=(uint8_t)bits;
        }
        if(dump&&(g_frame%64)==0)
            fprintf(stderr,"[F32] frm=%llu 0x%x %ux%u = %g %g %g %g\n",
                    (unsigned long long)g_frame,e->ea,e->w,e->h,
                    fp2[0],fp2[1],fp2[2],fp2[3]);
    }
    g_wbn[slot]=0; g_wbcmd[slot]=-1;
}

static int make_img_mip(uint32_t w, uint32_t h, uint32_t nmip, VkFormat fmt,
                        VkImageUsageFlags use, VkImageAspectFlags aspect,
                        VkImage* img, VkDeviceMemory* mem, VkImageView* view){
    if(!nmip) nmip=1;
    VkImageCreateInfo ici={.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .imageType=VK_IMAGE_TYPE_2D,.format=fmt,.extent={w,h,1},
        .mipLevels=nmip,.arrayLayers=1,.samples=1,.tiling=VK_IMAGE_TILING_OPTIMAL,
        .usage=use,.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED};
    if(vkCreateImage(g_dev,&ici,NULL,img)) return 0;
    VkMemoryRequirements mr; vkGetImageMemoryRequirements(g_dev,*img,&mr);
    uint32_t mt=mem_type(mr.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if(mt==UINT32_MAX) return 0;
    VkMemoryAllocateInfo mai={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize=mr.size,.memoryTypeIndex=mt};
    if(vkAllocateMemory(g_dev,&mai,NULL,mem)) return 0;
    if(vkBindImageMemory(g_dev,*img,*mem,0)) return 0;
    VkImageViewCreateInfo vci={.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
        .image=*img,.viewType=VK_IMAGE_VIEW_TYPE_2D,.format=fmt,
        .subresourceRange={aspect,0,nmip,0,1}};
    if(vkCreateImageView(g_dev,&vci,NULL,view)) return 0;
    return 1;
}
static int make_img(uint32_t w, uint32_t h, VkFormat fmt, VkImageUsageFlags use,
                    VkImageAspectFlags aspect, VkImage* img, VkDeviceMemory* mem,
                    VkImageView* view){
    return make_img_mip(w,h,1,fmt,use,aspect,img,mem,view);
}
static int make_img_tex(uint32_t w, uint32_t h, uint32_t d, uint32_t nmip,
                        int type, VkFormat fmt, VkImage* img,
                        VkDeviceMemory* mem, VkImageView* view){
    if(!nmip) nmip=1;
    if(!d) d=1;
    int cube=(type==FP_TEX_CUBE), vol=(type==FP_TEX_3D);
    uint32_t layers=cube?6u:1u;
    VkImageCreateInfo ici={.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .flags=cube?VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT:0,
        .imageType=vol?VK_IMAGE_TYPE_3D:VK_IMAGE_TYPE_2D,.format=fmt,
        .extent={w,h,vol?d:1},
        .mipLevels=nmip,.arrayLayers=layers,.samples=1,
        .tiling=VK_IMAGE_TILING_OPTIMAL,
        .usage=VK_IMAGE_USAGE_SAMPLED_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .initialLayout=VK_IMAGE_LAYOUT_UNDEFINED};
    if(vkCreateImage(g_dev,&ici,NULL,img)) return 0;
    VkMemoryRequirements mr; vkGetImageMemoryRequirements(g_dev,*img,&mr);
    uint32_t mt=mem_type(mr.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if(mt==UINT32_MAX) return 0;
    VkMemoryAllocateInfo mai={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize=mr.size,.memoryTypeIndex=mt};
    if(vkAllocateMemory(g_dev,&mai,NULL,mem)) return 0;
    if(vkBindImageMemory(g_dev,*img,*mem,0)) return 0;
    VkImageViewCreateInfo vci={.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
        .image=*img,
        .viewType=cube?VK_IMAGE_VIEW_TYPE_CUBE
                 :vol ?VK_IMAGE_VIEW_TYPE_3D:VK_IMAGE_VIEW_TYPE_2D,
        .format=fmt,
        .subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,nmip,0,layers}};
    if(vkCreateImageView(g_dev,&vci,NULL,view)) return 0;
    return 1;
}

static Surf* surf_get(uint32_t ea, uint32_t w, uint32_t h){
    for(int sl=g_surfhead[surf_hkey(ea)]; sl; sl=g_surf[sl-1].hnext){
        Surf* s=&g_surf[sl-1];
        if(s->ea==ea&&s->w==w&&s->h==h&&s->img){ s->last_frame=g_frame; return s; }
    }
    Surf* best=0;
    for(int i=0;i<NSURF;i++){
        if(!g_surf[i].img){ best=&g_surf[i]; break; }
        if(g_surf[i].last_frame==g_frame) continue;
        if(!best||g_surf[i].last_frame<best->last_frame) best=&g_surf[i];
    }
    if(!best){ static int wns; if(wns++<8)
        fprintf(stderr,"[RSXD] surface cache full this frame (>%d live) - "
                "bump NSURF\n",NSURF);
        return 0; }
    if(best->img){
        { static int wne; if(wne++<32)
            fprintf(stderr,"[RSXD] surface evict 0x%x %ux%u (last used frame "
                    "%llu, now %llu) to make room for 0x%x %ux%u\n",
                    best->ea,best->w,best->h,
                    (unsigned long long)best->last_frame,
                    (unsigned long long)g_frame,ea,w,h); }
        cmd_submit();
        vkDestroyFramebuffer(g_dev,best->fb,NULL);
        vkDestroyImageView(g_dev,best->view,NULL); vkDestroyImage(g_dev,best->img,NULL);
        vkFreeMemory(g_dev,best->mem,NULL);
        vkDestroyImageView(g_dev,best->zview,NULL); vkDestroyImage(g_dev,best->z,NULL);
        vkFreeMemory(g_dev,best->zmem,NULL);
        surf_unlink(best);
        memset(best,0,sizeof *best);
    }
    uint32_t sfmt=g_rsx.surface_format&0x1f;
    int isf=(sfmt==0xb||sfmt==0xc||sfmt==0xd);
    if(!make_img(w,h,isf?VK_FORMAT_R32G32B32A32_SFLOAT:VK_FORMAT_B8G8R8A8_UNORM,
        VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|VK_IMAGE_USAGE_TRANSFER_SRC_BIT|
        VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_SAMPLED_BIT,
        VK_IMAGE_ASPECT_COLOR_BIT,&best->img,&best->mem,&best->view)) return 0;
    if(!make_img(w,h,VK_FORMAT_D32_SFLOAT,
        VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT|VK_IMAGE_USAGE_SAMPLED_BIT,
        VK_IMAGE_ASPECT_DEPTH_BIT,&best->z,&best->zmem,&best->zview)) return 0;
    VkImageView att[2]={best->view,best->zview};
    VkFramebufferCreateInfo fci={.sType=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO,
        .renderPass=isf?g_rpf:g_rp,.attachmentCount=2,.pAttachments=att,
        .width=w,.height=h,.layers=1};
    if(vkCreateFramebuffer(g_dev,&fci,NULL,&best->fb)) return 0;
    best->ea=ea; best->w=w; best->h=h; best->isf=isf;
    best->inited=0; best->last_frame=g_frame;
    best->zfloat=1;
    surf_link(best);
    fprintf(stderr,"[RSXD] RT ea=0x%x %ux%u sfmt=0x%x%s\n",ea,w,h,sfmt,
            isf?" (float)":"");
    return best;
}

static void rp_begin(Surf* s){
    if(g_in_rp&&g_cur==s) return;
    rp_end();
    cmd_begin();
    if(!s->inited||s->layout!=0){
        VkImageLayout from = !s->inited ? VK_IMAGE_LAYOUT_UNDEFINED
            : (s->layout==1 ? VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                            : VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
        VkImageMemoryBarrier b[2]={
            {.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
             .srcAccessMask=s->inited?VK_ACCESS_SHADER_READ_BIT|VK_ACCESS_TRANSFER_READ_BIT:0,
             .dstAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
             .oldLayout=from,
             .newLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
             .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
             .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
             .image=s->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}},
            {.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
             .dstAccessMask=VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT,
             .oldLayout=VK_IMAGE_LAYOUT_UNDEFINED,
             .newLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
             .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
             .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
             .image=s->z,.subresourceRange={VK_IMAGE_ASPECT_DEPTH_BIT,0,1,0,1}}};
        int nb = s->inited ? 1 : 2;
        int first = !s->inited;
        vkCmdPipelineBarrier(g_cmd,stages_for(b[0].srcAccessMask|b[1].srcAccessMask,1),
            stages_for(b[0].dstAccessMask|b[1].dstAccessMask,0),0,0,0,0,0,nb,b);
        s->inited=1; s->layout=0;
        if(first){
            VkRenderPassBeginInfo rbi={.sType=VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
                .renderPass=s->isf?g_rpf:g_rp,.framebuffer=s->fb,
                .renderArea={{0,0},{s->w,s->h}}};
            vkCmdBeginRenderPass(g_cmd,&rbi,VK_SUBPASS_CONTENTS_INLINE);
            static int dbgclr=-1;
            if(dbgclr<0) dbgclr=getenv("PS3_RSXDBGCLR")?1:0;
            VkClearAttachment ca[2]={
                {.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.colorAttachment=0,
                 .clearValue={.color={.float32={dbgclr?1.0f:0,0,dbgclr?1.0f:0,1}}}},
                {.aspectMask=VK_IMAGE_ASPECT_DEPTH_BIT,
                 .clearValue={.depthStencil={1.0f,0}}}};
            VkClearRect cr={.rect={{0,0},{s->w,s->h}},.layerCount=1};
            vkCmdClearAttachments(g_cmd,2,ca,1,&cr);
            vkCmdEndRenderPass(g_cmd);
        }
    }
    VkRenderPassBeginInfo rbi={.sType=VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
        .renderPass=s->isf?g_rpf:g_rp,.framebuffer=s->fb,
        .renderArea={{0,0},{s->w,s->h}}};
    vkCmdBeginRenderPass(g_cmd,&rbi,VK_SUBPASS_CONTENTS_INLINE);
    g_in_rp=1; g_cur=s;
}

static Surf* current_rt(void){
    { static int mrtdbg=-1; if(mrtdbg<0) mrtdbg=getenv("PS3_RSX_MRTDBG")?1:0;
      if(mrtdbg){ static uint32_t last_ct=0xffffffffu;
        if(g_rsx.color_target!=last_ct){ last_ct=g_rsx.color_target;
            fprintf(stderr,"[MRT] target=0x%x A=0x%x/%u B=0x%x/%u C=0x%x/%u D=0x%x/%u fmt=0x%x\n",
                    g_rsx.color_target,
                    g_rsx.color[0].offset,g_rsx.color[0].pitch,
                    g_rsx.color[1].offset,g_rsx.color[1].pitch,
                    g_rsx.color[2].offset,g_rsx.color[2].pitch,
                    g_rsx.color[3].offset,g_rsx.color[3].pitch,g_rsx.surface_format); } } }
    uint32_t w=(g_rsx.clip_h>>16)&0xffff, h=(g_rsx.clip_v>>16)&0xffff;
    if(!w||!h||w>4096||h>4096) return 0;
    uint32_t loc=dma_loc(g_rsx.ctx_dma_color[0]);
    uint32_t ea=resolve(g_rsx.color[0].offset,loc);
    if(!ea) return 0;
    uint32_t zloc=dma_loc(g_rsx.ctx_dma_zeta);
    uint32_t zea=g_rsx.zeta.pitch?resolve(g_rsx.zeta.offset,zloc):0;
    if(zea&&(!(g_rsx.depth_test||g_rsx.depth_mask)||g_rsx.zeta.pitch<w*2u)) zea=0;
    Surf* rt=surf_get((zea&&!g_rsx.color_mask)?zea:ea,w,h);
    if(rt&&zea){
        if(rt->zea!=zea){ static int wnz; if(wnz++<32)
            fprintf(stderr,"[RSXD] surface 0x%x %ux%u zeta=0x%x pitch=%u\n",
                    rt->ea,rt->w,rt->h,zea,g_rsx.zeta.pitch); }
        rt->zea=zea; rt->zpitch=g_rsx.zeta.pitch;
    }
    return rt;
}

static VkRect2D scissor_rect(const Surf* rt){
    uint32_t sx=g_rsx.scissor_h&0xffff, sw=(g_rsx.scissor_h>>16)&0xffff;
    uint32_t sy=g_rsx.scissor_v&0xffff, sh=(g_rsx.scissor_v>>16)&0xffff;
    if(!sw||!sh){ sx=sy=0; sw=rt->w; sh=rt->h; }
    if(sx>=rt->w){ sx=0; sw=0; } else if(sx+sw>rt->w) sw=rt->w-sx;
    if(sy>=rt->h){ sy=0; sh=0; } else if(sy+sh>rt->h) sh=rt->h-sy;
    if(!sw||!sh){ sx=sy=0; sw=sh=0; }
    VkRect2D r={{(int32_t)sx,(int32_t)sy},{sw,sh}};
    return r;
}

static VkShaderModule make_module(const uint32_t* words, int n){
    VkShaderModuleCreateInfo ci={.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
        .codeSize=(size_t)n*4,.pCode=words};
    VkShaderModule mod;
    if(vkCreateShaderModule(g_dev,&ci,NULL,&mod)) return VK_NULL_HANDLE;
    return mod;
}

static VkBlendFactor blendf(uint32_t gl){
    switch(gl){
    case 0: return VK_BLEND_FACTOR_ZERO;
    case 1: return VK_BLEND_FACTOR_ONE;
    case 0x300: return VK_BLEND_FACTOR_SRC_COLOR;
    case 0x301: return VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR;
    case 0x302: return VK_BLEND_FACTOR_SRC_ALPHA;
    case 0x303: return VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    case 0x304: return VK_BLEND_FACTOR_DST_ALPHA;
    case 0x305: return VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA;
    case 0x306: return VK_BLEND_FACTOR_DST_COLOR;
    case 0x307: return VK_BLEND_FACTOR_ONE_MINUS_DST_COLOR;
    case 0x308: return VK_BLEND_FACTOR_SRC_ALPHA_SATURATE;
    case 0x8001: return VK_BLEND_FACTOR_CONSTANT_COLOR;
    case 0x8002: return VK_BLEND_FACTOR_ONE_MINUS_CONSTANT_COLOR;
    case 0x8003: return VK_BLEND_FACTOR_CONSTANT_ALPHA;
    case 0x8004: return VK_BLEND_FACTOR_ONE_MINUS_CONSTANT_ALPHA;
    default:
        { static int wn; if(wn++<8) fprintf(stderr,"[RSXD] blend factor 0x%x? ONE\n",gl); }
        return VK_BLEND_FACTOR_ONE;
    }
}
static VkBlendOp blendop(uint32_t gl){
    switch(gl){
    case 0x8006: return VK_BLEND_OP_ADD;
    case 0x8007: return VK_BLEND_OP_MIN;
    case 0x8008: return VK_BLEND_OP_MAX;
    case 0x800a: return VK_BLEND_OP_SUBTRACT;
    case 0x800b: return VK_BLEND_OP_REVERSE_SUBTRACT;
    default: return VK_BLEND_OP_ADD;
    }
}
static VkCompareOp cmpop(uint32_t gl){
    static const VkCompareOp T[8]={VK_COMPARE_OP_NEVER,VK_COMPARE_OP_LESS,
        VK_COMPARE_OP_EQUAL,VK_COMPARE_OP_LESS_OR_EQUAL,VK_COMPARE_OP_GREATER,
        VK_COMPARE_OP_NOT_EQUAL,VK_COMPARE_OP_GREATER_OR_EQUAL,VK_COMPARE_OP_ALWAYS};
    return T[gl&7];
}
static VkPrimitiveTopology topo(uint32_t prim){
    switch(prim){
    case 1: return VK_PRIMITIVE_TOPOLOGY_POINT_LIST;
    case 2: return VK_PRIMITIVE_TOPOLOGY_LINE_LIST;
    case 3: case 4: return VK_PRIMITIVE_TOPOLOGY_LINE_STRIP;
    case 5: case 8: case 9: case 10: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    case 6: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_STRIP;
    case 7: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_FAN;
    default: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    }
}

static uint32_t g_fp_words[16384];
static uint32_t g_fp_nwords;
static uint64_t g_fp_khash;
static uint32_t g_fp_epoch=1;
static uint32_t g_fp_memo_ea, g_fp_memo_epoch;
static int      g_fp_memo_valid;

#define FPC_N 512
typedef struct {
    uint32_t  key, ea, nwords, nins, nimm, cap;
    uint64_t  khash;
    uint8_t*  raw;
    uint32_t* words;
    uint32_t* ins;
    uint32_t* imm;
} FpCacheEnt;
static FpCacheEnt  g_fpc[FPC_N];
static FpCacheEnt* g_fpc_cur;

static int fpc_reserve(FpCacheEnt* e, uint32_t nw){
    if(nw<=e->cap) return 1;
    uint32_t cap=nw<64?64:nw;
    uint8_t* raw=(uint8_t*)realloc(e->raw,(size_t)cap*4);
    if(raw) e->raw=raw;
    uint32_t* w=(uint32_t*)realloc(e->words,(size_t)cap*4);
    if(w) e->words=w;
    uint32_t* in=(uint32_t*)realloc(e->ins,(size_t)cap*4);
    if(in) e->ins=in;
    uint32_t* im=(uint32_t*)realloc(e->imm,(size_t)cap*4);
    if(im) e->imm=im;
    if(!raw||!w||!in||!im) return 0;
    e->cap=cap; return 1;
}

static int fetch_fp(void){
    if(g_fp_memo_valid&&g_fp_memo_ea==g_rsx.fp_offset_raw&&
       g_fp_memo_epoch==g_fp_epoch){ g_dpfpmemo++; return g_fp_nwords>0; }
    uint32_t loc=((g_rsx.fp_offset_raw&3)==2)?GCM_LOCATION_MAIN:GCM_LOCATION_LOCAL;
    uint32_t ea=resolve(g_rsx.fp_offset_raw&~3u,loc);
    if(!ea){ g_fp_memo_valid=0; g_fpc_cur=0; return 0; }
    uint32_t key=g_rsx.fp_offset_raw;
    FpCacheEnt* e=&g_fpc[(key*2654435761u)>>23];
    const uint8_t* src=g_base+ea;
    if(e->nwords&&e->key==key&&e->ea==ea){
        int same=memcmp(e->raw,src,(size_t)e->nwords*4)==0;
        if(!same){
            same=1;
            for(uint32_t i=0;i<e->nins&&same;i++)
                same=memcmp(e->raw+e->ins[i]*4,src+e->ins[i]*4,16)==0;
            if(same)
                for(uint32_t i=0;i<e->nimm;i++){
                    uint32_t c=e->imm[i];
                    for(int k=0;k<4;k++) e->words[c+k]=fp_word(src+(c+k)*4);
                    memcpy(e->raw+c*4,src+c*4,16);
                }
        }
        if(same){
            memcpy(g_fp_words,e->words,(size_t)e->nwords*4);
            g_fp_nwords=e->nwords; g_fp_khash=e->khash; g_fpc_cur=e;
            g_fp_memo_ea=key; g_fp_memo_epoch=g_fp_epoch; g_fp_memo_valid=1;
            return 1;
        }
    }
    uint32_t maxw=sizeof g_fp_words/4;
    uint32_t iw=0, nins=0, nimm=0;
    static uint32_t ins[16384/4], imm[16384/4];
    uint64_t kh=0xcbf29ce484222325ull;
    while(iw+4<=maxw){
        for(int k=0;k<4;k++) g_fp_words[iw+k]=fp_word(g_base+ea+(iw+k)*4);
        FpInstr tmp;
        int used=fp_decode_instr(&g_fp_words[iw],&tmp);
        if(used==2&&iw+8>maxw) used=1;
        if(used==2)
            for(int k=4;k<8;k++) g_fp_words[iw+k]=fp_word(g_base+ea+(iw+k)*4);
        ins[nins++]=iw;
        if(used==2) imm[nimm++]=iw+4;
        kh=fnv1a(&g_fp_words[iw],16,kh);
        iw+=(uint32_t)used*4;
        if(tmp.end) break;
    }
    g_fp_nwords=iw;
    g_fp_khash=kh;
    g_fp_memo_ea=key; g_fp_memo_epoch=g_fp_epoch;
    g_fp_memo_valid=1;
    g_fpc_cur=0;
    if(iw&&fpc_reserve(e,iw)){
        e->key=key; e->ea=ea; e->nwords=iw; e->nins=nins; e->nimm=nimm; e->khash=kh;
        memcpy(e->raw,g_base+ea,(size_t)iw*4);
        memcpy(e->words,g_fp_words,(size_t)iw*4);
        memcpy(e->ins,ins,(size_t)nins*4);
        memcpy(e->imm,imm,(size_t)nimm*4);
        g_fpc_cur=e;
    } else e->nwords=0;
    return iw>0;
}
static uint32_t fp_consts(float (*out)[4], uint32_t cap){
    const FpCacheEnt* e=g_fpc_cur;
    if(!e) return fp_collect_consts(g_fp_words,g_fp_nwords,out,cap);
    uint32_t n=e->nimm<cap?e->nimm:cap;
    for(uint32_t i=0;i<n;i++) memcpy(out[i],&g_fp_words[e->imm[i]],16);
    return n;
}

static uint32_t attr_bytes(uint32_t type, uint32_t size);

static VkFormat attr_native_fmt(uint32_t type, uint32_t size){
    if(size<1||size>4) return VK_FORMAT_UNDEFINED;
    static const VkFormat f32[4]={VK_FORMAT_R32_SFLOAT,VK_FORMAT_R32G32_SFLOAT,
        VK_FORMAT_R32G32B32_SFLOAT,VK_FORMAT_R32G32B32A32_SFLOAT};
    static const VkFormat f16[4]={VK_FORMAT_R16_SFLOAT,VK_FORMAT_R16G16_SFLOAT,
        VK_FORMAT_R16G16B16_SFLOAT,VK_FORMAT_R16G16B16A16_SFLOAT};
    static const VkFormat s16[4]={VK_FORMAT_R16_SNORM,VK_FORMAT_R16G16_SNORM,
        VK_FORMAT_R16G16B16_SNORM,VK_FORMAT_R16G16B16A16_SNORM};
    static const VkFormat u8 [4]={VK_FORMAT_R8_UNORM,VK_FORMAT_R8G8_UNORM,
        VK_FORMAT_R8G8B8_UNORM,VK_FORMAT_R8G8B8A8_UNORM};
    switch(type){
    case 1: return s16[size-1];
    case 2: return f32[size-1];
    case 3: return f16[size-1];
    case 4: return u8 [size-1];
    default: return VK_FORMAT_UNDEFINED;
    }
}
static int fmt_ok_for_vertex(VkFormat f){
    if(f==VK_FORMAT_UNDEFINED) return 0;
    static VkFormat seen[32]; static int ok[32]; static int n;
    for(int i=0;i<n;i++) if(seen[i]==f) return ok[i];
    VkFormatProperties fp; vkGetPhysicalDeviceFormatProperties(g_phys,f,&fp);
    int r=(fp.bufferFeatures&VK_FORMAT_FEATURE_VERTEX_BUFFER_BIT)?1:0;
    if(!r){ static int wn; if(wn++<8) fprintf(stderr,
        "[RSXD] vertex format %d unsupported on this device - attribute stays "
        "on the float path\n",(int)f); }
    if(n<32){ seen[n]=f; ok[n]=r; n++; }
    return r;
}
static void attr_layout(uint32_t a, VkFormat* fmt, uint32_t* stride, int* native){
    uint32_t f=g_rsx.vtx[a].format;
    uint32_t type=f&0xf, size=(f>>4)&0xf;
    if(size>4) size=4;
    VkFormat nf=VK_FORMAT_UNDEFINED;
    if(type&&size){
        nf=attr_native_fmt(type,size);
        if(!fmt_ok_for_vertex(nf)) nf=VK_FORMAT_UNDEFINED;
    }
    if(nf==VK_FORMAT_UNDEFINED){
        *fmt=VK_FORMAT_R32G32B32A32_SFLOAT; *stride=16;
        if(native) *native=0;
    } else {
        *fmt=nf; *stride=attr_bytes(type,size);
        if(native) *native=1;
    }
}

static VkPipeline pipe_get(uint32_t prim, uint32_t attr_present_mask, int isf,
                           uint32_t* out_used_attrs, uint32_t* out_tex_used,
                           uint32_t* out_vtex_used, uint32_t* out_nconst){
    DP_T0(t_key);
    uint64_t h=0xcbf29ce484222325ull ^ (isf?0x5aa5ull:0);
    uint32_t start=g_rsx.vp_start&0x1ff;
    static uint64_t vp_h; static uint32_t vp_n, vp_start=~0u, vp_epoch;
    if(start!=vp_start||g_vp_instr_epoch!=vp_epoch){
        uint32_t n=0;
        for(uint32_t i=start;i<512;i++){ n++;
            if(g_rsx.vp_instr[i][3]&1) break; }
        vp_h=hash_u32s(&g_rsx.vp_instr[start][0],(size_t)n*4,0x9e3779b97f4a7c15ull);
        vp_n=n; vp_start=start; vp_epoch=g_vp_instr_epoch;
    }
    uint32_t nvp=vp_n;
    { uint32_t vw[2]={(uint32_t)vp_h,(uint32_t)(vp_h>>32)}; h=hash_u32s(vw,2,h); }
    DP_T1(DP_KEY,t_key);
    DP_T0(t_fp);
    int fp_ok=fetch_fp();
    DP_T1(DP_FP,t_fp);
    if(!fp_ok) return VK_NULL_HANDLE;
    DP_T0(t_key2);
    { uint32_t kw[2]={(uint32_t)g_fp_khash,(uint32_t)(g_fp_khash>>32)}; h=hash_u32s(kw,2,h); }
    uint32_t st[23]={prim|(g_rsx.restart_en?0x100u:0u),attr_present_mask,
        g_rsx.blend_enable,g_rsx.blend_sfactor,
        g_rsx.blend_dfactor,g_rsx.blend_eq,g_rsx.depth_test,g_rsx.depth_func,
        g_rsx.depth_mask,g_rsx.cull_enable,g_rsx.cull_face,g_rsx.front_face,
        g_rsx.fp_control,g_rsx.color_mask,0,g_rsx.color_target,
        g_rsx.alpha_test,g_rsx.alpha_test?g_rsx.alpha_func:0,
        g_rsx.alpha_test?g_rsx.alpha_ref:0,
        (prim==1)?g_rsx.point_sprite:0u,
        g_rsx.poly_offs_fill,
        g_rsx.poly_offs_fill?f2u(g_rsx.poly_offs_scale):0,
        g_rsx.poly_offs_fill?f2u(g_rsx.poly_offs_bias):0};
    for(int a=0;a<16;a++) st[14]^=g_rsx.vtx[a].format*(uint32_t)(a*2654435761u+2246822519u);
    h=hash_u32s(st,sizeof st/4,h);
    uint32_t tk[64];
    for(int u=0;u<16;u++){ tk[u*4]=g_rsx.tex[u].control1;
        uint32_t zf=tex_zfunc(u); tk[u*4+1]=zf;
        tk[u*4+2]=zf?(uint32_t)tex_filter_linear(u):0u;
        tk[u*4+3]=(uint32_t)tex_target(u); }
    h=hash_u32s(tk,64,h);
    uint32_t buck=(uint32_t)h&(NPIPEBUCK-1);
    for(int s=g_pipe_head[buck]; s; s=g_pipe[s-1].next){
        Pipe* p=&g_pipe[s-1];
        if(p->key!=h) continue;
        p->last_use=++g_pipe_clock;
        *out_used_attrs=p->used_attrs;
        *out_tex_used=p->tex_used;
        *out_vtex_used=p->vtex_used;
        *out_nconst=p->nconst;
        DP_T1(DP_KEY,t_key2);
        return p->pipe; }
    DP_T1(DP_KEY,t_key2);
    DP_T0(t_build);
    if(dprof_on()){
        static uint64_t kseen[4096]; static int nk;
        int found=0;
        for(int i=0;i<nk;i++) if(kseen[i]==g_fp_khash){ found=1; break; }
        if(!found&&nk<4096) kseen[nk++]=g_fp_khash;
        g_dpfpstruct=nk;
    }

    static uint32_t vs_spv[262144], fs_spv[262144];
    { static int dumpn=-1;
      if(dumpn<0){ const char* e=getenv("PS3_RSX_DUMPVS"); dumpn=e?atoi(e):0; }
      if(dumpn>0){ dumpn--;
          char pth[64]; static int dk;
          snprintf(pth,sizeof pth,"out/vp_%d.bin",dk);
          FILE* f=fopen(pth,"wb");
          if(f){ for(uint32_t i2=start;i2<start+nvp&&i2<512;i2++)
                     fwrite(g_rsx.vp_instr[i2],1,16,f);
                 fclose(f); }
          snprintf(pth,sizeof pth,"out/fp_%d.bin",dk);
          f=fopen(pth,"wb");
          if(f){ fwrite(g_fp_words,4,g_fp_nwords,f); fclose(f); }
          dk++;
      } }
    FpProgramSrc fps={.words=g_fp_words,.nwords=g_fp_nwords,.ctrl=g_rsx.fp_control,
        .alpha_func=g_rsx.alpha_test?g_rsx.alpha_func:0,
        .alpha_ref=g_rsx.alpha_ref,
        .point_sprite=(prim==1)?g_rsx.point_sprite:0u};
    for(int u=0;u<16;u++){ fps.shadow[u]=(uint8_t)tex_zfunc(u);
        fps.shadow_linear[u]=fps.shadow[u]?(uint8_t)tex_filter_linear(u):0;
        fps.tex_type[u]=(uint8_t)tex_target(u); }
    for(int u=0;u<16;u++) fps.remap[u]=g_rsx.tex[u].control1;
    FpMeta meta;
    int nfs=fp_translate(&fps,fs_spv,262144,&meta);
    if(!nfs){ static int wn2; if(wn2++<16) fprintf(stderr,"[RSXD] fp_translate failed\n"); return VK_NULL_HANDLE; }
    VpProgram vp={.instr=(const uint32_t(*)[4])g_rsx.vp_instr,.start=start,.nconst=468};
    uint32_t used=0, outs=0, vtexu=0;
    int nvs=vp_translate(&vp,vs_spv,262144,&used,&outs,&vtexu);
    if(!nvs){ static int wn; if(wn++<16) fprintf(stderr,"[RSXD] vp_translate failed\n"); return VK_NULL_HANDLE; }
    { static int flatfs=-1, passvs=-1;
      if(flatfs<0){ flatfs=getenv("PS3_RSX_FLATFS")?1:0;
                    passvs=getenv("PS3_RSX_PASSVS")?1:0; }
      if(flatfs){ int n2=dbg_flat_fs(fs_spv,262144); if(n2) nfs=n2; }
      static int uvfs=-1, texfs=-1;
      if(uvfs<0){ uvfs=getenv("PS3_RSX_UVFS")?1:0; texfs=getenv("PS3_RSX_TEXFS")?1:0; }
      if(uvfs){ int n2=dbg_uv_fs(fs_spv,262144); if(n2) nfs=n2; }
      if(texfs){ int n2=dbg_tex_fs(fs_spv,262144); if(n2){ nfs=n2; meta.tex_used|=1; } }
      if(passvs){ int n2=dbg_passthru_vs(vs_spv,262144); if(n2){ nvs=n2; used=1; } }
      static const char* fsfile=(const char*)-1;
      if(fsfile==(const char*)-1) fsfile=getenv("PS3_RSX_FSFILE");
      if(fsfile){ FILE* ff=fopen(fsfile,"rb");
          if(ff){ size_t n3=fread(fs_spv,4,262144,ff); fclose(ff);
                  nfs=(int)n3; meta.tex_used|=1; } } }
    VkShaderModule vm=make_module(vs_spv,nvs), fm=make_module(fs_spv,nfs);
    if(!vm||!fm) return VK_NULL_HANDLE;

    VkPipelineShaderStageCreateInfo stg[2]={
        {.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
         .stage=VK_SHADER_STAGE_VERTEX_BIT,.module=vm,.pName="main"},
        {.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
         .stage=VK_SHADER_STAGE_FRAGMENT_BIT,.module=fm,.pName="main"}};
    VkVertexInputBindingDescription vb[16]; VkVertexInputAttributeDescription va[16];
    uint32_t nva=0;
    for(uint32_t a=0;a<16;a++) if(used&(1u<<a)){
        VkFormat afmt; uint32_t astride;
        attr_layout(a,&afmt,&astride,0);
        vb[nva]=(VkVertexInputBindingDescription){.binding=nva,.stride=astride,
            .inputRate=VK_VERTEX_INPUT_RATE_VERTEX};
        va[nva]=(VkVertexInputAttributeDescription){.location=a,.binding=nva,
            .format=afmt,.offset=0};
        nva++;
    }
    VkPipelineVertexInputStateCreateInfo vin={.sType=VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO,
        .vertexBindingDescriptionCount=nva,.pVertexBindingDescriptions=vb,
        .vertexAttributeDescriptionCount=nva,.pVertexAttributeDescriptions=va};
    VkPipelineInputAssemblyStateCreateInfo ia={.sType=VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
        .topology=topo(prim),
        .primitiveRestartEnable=(g_rsx.restart_en&&(prim==6||prim==7||prim==3||prim==4))
                                ?VK_TRUE:VK_FALSE};
    VkPipelineViewportStateCreateInfo vpst={.sType=VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
        .viewportCount=1,.scissorCount=1};
    static int nodepth=-1, noblend=-1, nocull=-1;
    if(nodepth<0){ nodepth=getenv("PS3_RSX_NODEPTH")?1:0;
                   noblend=getenv("PS3_RSX_NOBLEND")?1:0;
                   nocull=getenv("PS3_RSX_NOCULL")?1:0; }
    VkPipelineRasterizationStateCreateInfo rs={.sType=VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
        .polygonMode=VK_POLYGON_MODE_FILL,
        .cullMode=(g_rsx.cull_enable&&!nocull)?((g_rsx.cull_face==0x405)?VK_CULL_MODE_BACK_BIT:
                   (g_rsx.cull_face==0x404)?VK_CULL_MODE_FRONT_BIT:
                   VK_CULL_MODE_FRONT_AND_BACK):VK_CULL_MODE_NONE,
        .frontFace=(g_rsx.front_face==0x900)?VK_FRONT_FACE_CLOCKWISE
                                            :VK_FRONT_FACE_COUNTER_CLOCKWISE,
        .depthBiasEnable=g_rsx.poly_offs_fill?VK_TRUE:VK_FALSE,
        .depthBiasConstantFactor=g_rsx.poly_offs_bias*zbias_scale(),
        .depthBiasSlopeFactor=g_rsx.poly_offs_scale,
        .lineWidth=1.0f};
    { static int seen=-1;
      if(g_rsx.poly_offs_fill&&seen<0){ seen=1;
        fprintf(stderr,"[RSXD] polygon offset enabled: slope=%g constant=%g "
                "(x%g)\n",g_rsx.poly_offs_scale,g_rsx.poly_offs_bias,
                zbias_scale()); } }
    VkPipelineMultisampleStateCreateInfo ms={.sType=VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
        .rasterizationSamples=VK_SAMPLE_COUNT_1_BIT};
    VkPipelineDepthStencilStateCreateInfo ds={.sType=VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO,
        .depthTestEnable=(g_rsx.depth_test&&!nodepth)?VK_TRUE:VK_FALSE,
        .depthWriteEnable=g_rsx.depth_mask?VK_TRUE:VK_FALSE,
        .depthCompareOp=cmpop(g_rsx.depth_func)};
    VkPipelineColorBlendAttachmentState ba={
        .blendEnable=(g_rsx.blend_enable&&!noblend)?VK_TRUE:VK_FALSE,
        .srcColorBlendFactor=blendf(g_rsx.blend_sfactor&0xffff),
        .dstColorBlendFactor=blendf(g_rsx.blend_dfactor&0xffff),
        .colorBlendOp=blendop(g_rsx.blend_eq&0xffff),
        .srcAlphaBlendFactor=blendf(g_rsx.blend_sfactor>>16),
        .dstAlphaBlendFactor=blendf(g_rsx.blend_dfactor>>16),
        .alphaBlendOp=blendop(g_rsx.blend_eq>>16),
        .colorWriteMask=(g_rsx.color_target==0)?0:
                        (((g_rsx.color_mask>>16)&1?VK_COLOR_COMPONENT_R_BIT:0)|
                         ((g_rsx.color_mask>>8)&1?VK_COLOR_COMPONENT_G_BIT:0)|
                         ((g_rsx.color_mask>>0)&1?VK_COLOR_COMPONENT_B_BIT:0)|
                         ((g_rsx.color_mask>>24)&1?VK_COLOR_COMPONENT_A_BIT:0))};
    VkPipelineColorBlendStateCreateInfo cb={.sType=VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
        .attachmentCount=1,.pAttachments=&ba};
    VkDynamicState dyn[2]={VK_DYNAMIC_STATE_VIEWPORT,VK_DYNAMIC_STATE_SCISSOR};
    VkPipelineDynamicStateCreateInfo dst={.sType=VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO,
        .dynamicStateCount=2,.pDynamicStates=dyn};
    VkGraphicsPipelineCreateInfo pci={.sType=VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO,
        .stageCount=2,.pStages=stg,.pVertexInputState=&vin,
        .pInputAssemblyState=&ia,.pViewportState=&vpst,
        .pRasterizationState=&rs,.pMultisampleState=&ms,
        .pDepthStencilState=&ds,.pColorBlendState=&cb,.pDynamicState=&dst,
        .layout=g_playout,.renderPass=isf?g_rpf:g_rp,.subpass=0};
    VkPipeline pipe;
    VkResult r=vkCreateGraphicsPipelines(g_dev,VK_NULL_HANDLE,1,&pci,NULL,&pipe);
    vkDestroyShaderModule(g_dev,vm,NULL); vkDestroyShaderModule(g_dev,fm,NULL);
    if(r){ fprintf(stderr,"[RSXD] pipeline create -> %d\n",(int)r); return VK_NULL_HANDLE; }
    g_dppipenew++;
    int slot;
    if(g_npipe<NPIPE) slot=g_npipe++;
    else {
        slot=0;
        for(int i=1;i<NPIPE;i++)
            if(g_pipe[i].last_use<g_pipe[slot].last_use) slot=i;
        uint32_t ob=(uint32_t)g_pipe[slot].key&(NPIPEBUCK-1);
        for(int* pp=&g_pipe_head[ob]; *pp; pp=&g_pipe[*pp-1].next)
            if(*pp-1==slot){ *pp=g_pipe[slot].next; break; }
        if(g_nretired<(int)(sizeof g_pipe_retired/sizeof g_pipe_retired[0]))
            g_pipe_retired[g_nretired++]=g_pipe[slot].pipe;
        else { cmd_submit();
               vkDestroyPipeline(g_dev,g_pipe[slot].pipe,NULL); }
        g_dppipeevict++;
        { static int wn; if(wn++<8) fprintf(stderr,
            "[RSXD] pipeline cache full (%d entries) - evicting LRU. If this "
            "repeats, the working set exceeds NPIPE; raise it.\n",NPIPE); }
    }
    g_pipe[slot].key=h; g_pipe[slot].pipe=pipe;
    g_pipe[slot].used_attrs=used; g_pipe[slot].tex_used=meta.tex_used;
    g_pipe[slot].vtex_used=vtexu; g_pipe[slot].nconst=meta.nconst;
    g_pipe[slot].last_use=++g_pipe_clock;
    g_pipe[slot].next=g_pipe_head[buck]; g_pipe_head[buck]=slot+1;
    *out_used_attrs=used;
    *out_tex_used=meta.tex_used;
    *out_vtex_used=vtexu;
    *out_nconst=meta.nconst;
    { static int np; if(++np<=64)
        fprintf(stderr,"[RSXD] pipeline #%d prim=%u attrs=0x%x vs=%dw fs=%dw"
                " atest=%u/0x%x/0x%02x kil=%d\n",
                np,prim,used,nvs,nfs,
                g_rsx.alpha_test,g_rsx.alpha_test?g_rsx.alpha_func:0,
                g_rsx.alpha_test?g_rsx.alpha_ref:0,meta.kil); }
    DP_T1(DP_BUILD,t_build);
    return pipe;
}

static VkSamplerAddressMode wrapmode(uint32_t g){
    switch(g){
    case 1: return VK_SAMPLER_ADDRESS_MODE_REPEAT;
    case 2: return VK_SAMPLER_ADDRESS_MODE_MIRRORED_REPEAT;
    case 3: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    case 4: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER;
    case 5: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER;
    case 6: case 7: case 8:
        return rsxvk_have_mirror_clamp()
             ? VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE
             : VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    default: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    }
}
static VkSampler sampler_get(uint32_t unit, uint32_t nmip, int shadow){
    uint32_t filt=g_rsx.tex[unit].filter, addr=g_rsx.tex[unit].address;
    uint32_t mag=(filt>>24)&0xf, min=(filt>>16)&0xf;
    uint32_t ws=addr&0xf, wt=(addr>>8)&0xf;
    if(shadow){ mag=1; min=1; nmip=1; }
    if(!nmip) nmip=1;
    uint32_t bc=g_rsx.tex[unit].border_color;
    uint32_t bsel=0;
    if(((bc>>16)&0xff)>=128&&((bc>>8)&0xff)>=128&&(bc&0xff)>=128) bsel=2;
    else if(((bc>>24)&0xff)>=128) bsel=1;
    uint32_t ctl0=g_rsx.tex[unit].control0;
    float lod_max=(float)((ctl0>>7)&0xfff)/256.0f;
    float lod_min=(float)((ctl0>>19)&0xfff)/256.0f;
    if(shadow||!(ctl0>>31)){ lod_min=0.0f; lod_max=(float)(nmip-1); }
    if(lod_max>(float)(nmip-1)) lod_max=(float)(nmip-1);
    if(lod_min>lod_max) lod_min=lod_max;
    { static int ml0=-1; if(ml0<0) ml0=getenv("PS3_RSX_MAXLOD0")?1:0;
      if(ml0){ lod_min=0.0f; lod_max=0.0f; } }
    { static int mln=-2; if(mln==-2){ const char* e=getenv("PS3_RSX_MINLOD");
        mln=e?atoi(e):-1; }
      if(mln>=0&&!shadow&&nmip>1){ lod_min=(float)mln;
          if(lod_min>lod_max) lod_min=lod_max; } }
    uint32_t lodbits=(shadow||!(ctl0>>31))?0u:((ctl0>>7)&0xffffff);
    uint64_t key=((uint64_t)lodbits<<32)|
                 (bsel<<20)|(nmip<<22)|(mag<<12)|(min<<8)|(ws<<4)|wt;
    { uint32_t b=samp_hslot(key);
      for(uint32_t p=0;p<NSAMPH;p++){
          int s2=g_samph[(b+p)&(NSAMPH-1)];
          if(!s2) break;
          if(g_samp[s2-1].key==key) return g_samp[s2-1].s;
      } }
    VkSamplerCreateInfo sci={.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO,
        .magFilter=(mag==1)?VK_FILTER_NEAREST:VK_FILTER_LINEAR,
        .minFilter=(min==1||min==3||min==5)?VK_FILTER_NEAREST:VK_FILTER_LINEAR,
        .mipmapMode=(min==5||min==6)?VK_SAMPLER_MIPMAP_MODE_LINEAR
                                    :VK_SAMPLER_MIPMAP_MODE_NEAREST,
        .addressModeU=wrapmode(ws),.addressModeV=wrapmode(wt),
        .addressModeW=VK_SAMPLER_ADDRESS_MODE_REPEAT,
        .borderColor=(bsel==2)?VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE:
                     (bsel==1)?VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK:
                               VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK,
        .minLod=lod_min,.maxLod=lod_max};
    VkSampler s;
    if(vkCreateSampler(g_dev,&sci,NULL,&s)) return g_sampler;
    { static long ns; if(++ns<=64)
        fprintf(stderr,"[SAMP] u%u min=%u mag=%u wrap=%u/%u lod=%.2f..%.2f "
                "nmip=%u bias=0x%03x\n",unit,min,mag,ws,wt,
                (double)lod_min,(double)lod_max,nmip,filt&0x1fff); }
    if(g_nsamp<NSAMP){ g_samp[g_nsamp].key=key; g_samp[g_nsamp].s=s; g_nsamp++;
        uint32_t b=samp_hslot(key);
        for(uint32_t p=0;p<NSAMPH;p++){
            uint32_t i2=(b+p)&(NSAMPH-1);
            if(!g_samph[i2]){ g_samph[i2]=g_nsamp; break; }
        } }
    else { static int wn; if(wn++<1) fprintf(stderr,"[RSXD] sampler cache full\n");
           vkDestroySampler(g_dev,s,NULL); return g_sampler; }
    return s;
}

#define cube_face_stride tex_cube_face_stride

static uint32_t tex_qhash(uint32_t ea, uint32_t bytes){
    uint32_t h=2166136261u;
    uint64_t avail=(g_mem_size>(uint64_t)ea)?g_mem_size-(uint64_t)ea:0;
    if((uint64_t)bytes>avail) bytes=(uint32_t)avail;
    uint32_t step=bytes>256?bytes/64:4;
    for(uint32_t o=0;o+4<=bytes;o+=step){ h^=rd32(ea+o); h*=16777619u; }
    return h;
}

static VkImageView rt_as_tex(uint32_t ea, uint32_t w, uint32_t h){
    Surf* best=0; Surf* wrong_size=0;
    for(int sl=g_surfhead[surf_hkey(ea)]; sl; sl=g_surf[sl-1].hnext){
        Surf* c2=&g_surf[sl-1];
        if(!c2->img||!c2->inited||c2->ea!=ea) continue;
        if(!w||!h||(c2->w==w&&c2->h==h)){ best=c2; break; }
        if(!wrong_size||c2->last_frame>wrong_size->last_frame) wrong_size=c2;
    }
    if(!best&&wrong_size){ static int wn2; if(wn2++<16)
        fprintf(stderr,"[RSXD] tex 0x%x %ux%u: surface at that EA is %ux%u - "
                "not aliasing it, reading guest memory instead\n",
                ea,w,h,wrong_size->w,wrong_size->h); }
    if(!best){
        for(int i=0;i<NSURF;i++){
            Surf* c2=&g_surf[i];
            if(!c2->img||!c2->inited) continue;
            uint64_t span=(uint64_t)c2->w*c2->h*4;
            if(ea<c2->ea||ea>=c2->ea+span) continue;
            uint32_t off=ea-c2->ea, rowb=c2->w*4;
            if(off%rowb) continue;
            if(w&&w!=c2->w) continue;
            if(h&&off/rowb+h>c2->h) continue;
            if(!best||c2->last_frame>best->last_frame) best=c2;
        }
        if(best){ static int wn; if(wn++<8)
            fprintf(stderr,"[RSXD] tex ea=0x%x aliases surface 0x%x (%ux%u) at +0x%x\n",
                    ea,best->ea,best->w,best->h,ea-best->ea); }
    }
    {
        Surf* sf=best;
        if(sf){
            if(sf->layout!=1){
                rp_end(); cmd_begin();
                VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                    .srcAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
                    .dstAccessMask=VK_ACCESS_SHADER_READ_BIT,
                    .oldLayout=sf->layout==2?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
                                            :VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
                    .newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL,
                    .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                    .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                    .image=sf->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
                vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
                sf->layout=1;
            }
            sf->last_frame=g_frame;
            return sf->view;
        }
    }
    return 0;
}

static uint32_t tex_hkey(uint32_t ea, uint32_t fmt, uint32_t rect, uint32_t ctl3){
    uint32_t h = ea*2654435761u ^ fmt*2246822519u ^ rect*3266489917u
               ^ ctl3*668265263u;
    return (h ^ (h>>15)) & (NTEXHASH-1);
}
static void tex_unlink(Tex* x){
    int* p=&g_texhead[tex_hkey(x->ea,x->fmt,x->rect,x->ctl3)];
    while(*p){ Tex* c=&g_tex[*p-1];
        if(c==x){ *p=c->hnext; c->hnext=0; return; }
        p=&c->hnext; }
}
static void tex_link(Tex* x){
    uint32_t b=tex_hkey(x->ea,x->fmt,x->rect,x->ctl3);
    x->hnext=g_texhead[b];
    g_texhead[b]=(int)(x-g_tex)+1;
}
static int tex_live(const Tex* x){
    return x->use_frame==g_frame && x->use_drain==g_tex_drain;
}
static void tex_free(Tex* x){
    tex_unlink(x);
    vkDestroyImageView(g_dev,x->view,NULL);
    vkDestroyImage(g_dev,x->img,NULL);
    vkFreeMemory(g_dev,x->mem,NULL);
    memset(x,0,sizeof *x);
}
static void tex_retire(void){
    if(g_up<=0) return;
    uint64_t tot=0; int live=0;
    for(int i=0;i<NTEX;i++){ Tex* c=&g_tex[i];
        if(!c->img) continue;
        tot+=c->bytes;
        if(tex_live(c)) live++; }
    { static int hi; if(live>hi){ hi=live;
        fprintf(stderr,"[RSXD] texture working set %d/%d slots, %llu MB"
                " (frame %llu)\n",live,NTEX,(unsigned long long)(tot>>20),
                (unsigned long long)g_frame); } }
    static uint64_t cap;
    if(!cap){
        const char* e=getenv("PS3_RSX_TEXMB");
        if(e&&atoi(e)>0) cap=(uint64_t)atoi(e)<<20;
        else{
            VkPhysicalDeviceMemoryProperties mp;
            vkGetPhysicalDeviceMemoryProperties(g_phys,&mp);
            VkDeviceSize heap=0;
            for(uint32_t i=0;i<mp.memoryHeapCount;i++)
                if((mp.memoryHeaps[i].flags&VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)&&
                   mp.memoryHeaps[i].size>heap) heap=mp.memoryHeaps[i].size;
            cap=(uint64_t)heap*45/100;
            if(cap<(512ull<<20)) cap=512ull<<20;
            if(cap>(2048ull<<20)) cap=2048ull<<20;
        }
        fprintf(stderr,"[RSXD] texture cache: %d slots, %llu MB budget\n",
                NTEX,(unsigned long long)(cap>>20));
    }
    if(tot<=cap) return;
    cmd_submit();
    while(tot>cap){
        Tex* v=0;
        for(int i=0;i<NTEX;i++){ Tex* c=&g_tex[i];
            if(!c->img||tex_live(c)) continue;
            if(!v||c->last_frame<v->last_frame) v=c; }
        if(!v) break;
        tot-=v->bytes;
        { static long n; if(n++<32)
            fprintf(stderr,"[RSXD] texture retire ea=0x%x %ux%u %llu KB "
                    "(last used frame %llu; %llu MB left)\n",
                    v->ea,(v->rect>>16)&0xffff,v->rect&0xffff,
                    (unsigned long long)(v->bytes>>10),
                    (unsigned long long)v->last_frame,
                    (unsigned long long)(tot>>20)); }
        tex_free(v);
    }
}

static Tex* tex_get(uint32_t unit){
    RsxTexture* t=&g_rsx.tex[unit];
    if(!(t->control0>>31)){ static int wnd; if(wnd++<16)
        fprintf(stderr,"[RSXD] tex u%u DISABLED (ctl0=0x%x fmt=0x%x rect=0x%x)\n",
                unit,t->control0,t->format,t->image_rect);
        return 0; }
    uint32_t fmtw=t->format;
    uint32_t loc=(fmtw&3)-1, dim=(fmtw>>4)&0xf, cube=(fmtw>>2)&1;
    uint32_t fmt=(fmtw>>8)&0xff;
    uint32_t w=(t->image_rect>>16)&0xffff, h=t->image_rect&0xffff;
    uint32_t pitch=t->control3&0xfffff;
    if(!w||!h||w>4096||h>4096){ static int wn0; if(wn0++<16)
        fprintf(stderr,"[RSXD] tex u%u bad rect %ux%u (ctl0=0x%x fmt=0x%x)\n",
                unit,w,h,t->control0,fmtw);
        return 0; }
    int type = cube ? FP_TEX_CUBE : (dim==3 ? FP_TEX_3D : FP_TEX_2D);
    uint32_t depth = (type==FP_TEX_3D) ? (t->control3>>20) : 1u;
    if(!depth) depth=1;
    if(depth>512){ static int wnv; if(wnv++<8)
        fprintf(stderr,"[RSXD] 3D texture unit %u depth %u exceeds the 512 the "
                "manual allows - clamping\n",unit,depth);
        depth=512; }
    if(type==FP_TEX_3D&&tex_is_dxt(fmt)){ static int wnc; if(wnc++<8)
        fprintf(stderr,"[RSXD] 3D DXT texture unit %u is VTC-packed - not "
                "decoded (manual 7.2.6.4); slice 0 only\n",unit);
        depth=1; }
    uint32_t ea=resolve(t->offset,loc);
    if(!ea){ static int wnr; if(wnr++<16)
        fprintf(stderr,"[RSXD] tex u%u unresolvable off=0x%x loc=%u\n",unit,t->offset,loc);
        return 0; }
    uint32_t bytes = tex_level_bytes(fmt,w,h,depth,pitch);
    if(type==FP_TEX_CUBE) bytes*=6;
    uint32_t nmip=(fmtw>>16)&0xff;
    { uint32_t maxlev=1, d=(w>h)?w:h; if(depth>d) d=depth;
      while(d>1){ d>>=1; maxlev++; }
      if(nmip<1) nmip=1;
      if(nmip>maxlev) nmip=maxlev;
      if(GCM_TEX_LN(fmt)) nmip=1; }
    if(type==FP_TEX_CUBE&&nmip>1&&GCM_TEX_LN(fmt)) nmip=1;
    uint32_t qh=tex_qhash(ea,bytes);
    Tex* found=0;
    for(int sl=g_texhead[tex_hkey(ea,fmtw,t->image_rect,t->control3)];
        sl; sl=g_tex[sl-1].hnext){
        Tex* x=&g_tex[sl-1];
        if(!(x->ready&&x->ea==ea&&x->fmt==fmtw&&x->rect==t->image_rect&&
             x->ctl3==t->control3)) continue;
        if(x->qhash==qh){ x->last_frame=x->use_frame=g_frame;
                          x->use_drain=g_tex_drain; return x; }
        if(!tex_live(x)) found=x;
        break;
    }
    Tex* x=found;
    if(!x){
        for(int pass=0;pass<2&&!x;pass++){
            if(pass){
                cmd_submit(); g_tex_drain++;
                static int wnt; if(wnt++<8)
                    fprintf(stderr,"[RSXD] all %d texture slots live mid-frame "
                            "- drained to recycle; raise NTEX if this repeats "
                            "every frame\n",NTEX);
            }
            for(int i=0;i<NTEX;i++){
                if(!g_tex[i].ready&&!g_tex[i].img){ x=&g_tex[i]; break; }
                if(!pass&&tex_live(&g_tex[i])) continue;
                if(!x||g_tex[i].last_frame<x->last_frame) x=&g_tex[i];
            }
        }
        if(!x) return 0;
        if(x->img){ cmd_submit(); tex_free(x); }
        if(!make_img_tex(w,h,depth,nmip,type,VK_FORMAT_B8G8R8A8_UNORM,
                         &x->img,&x->mem,&x->view)) return 0;
        VkMemoryRequirements mrq;
        vkGetImageMemoryRequirements(g_dev,x->img,&mrq);
        x->bytes=mrq.size;
    }
    uint32_t faces = (type==FP_TEX_CUBE) ? 6u : 1u;
    uint32_t face_stride = (type==FP_TEX_CUBE)
                         ? cube_face_stride(fmt,w,h,nmip,pitch) : 0u;
    rp_end(); cmd_begin();
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=x->ready?VK_ACCESS_SHADER_READ_BIT:0,
        .dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
        .oldLayout=x->ready?VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                           :VK_IMAGE_LAYOUT_UNDEFINED,
        .newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=x->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,nmip,0,faces}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    uint64_t l0sum=0; int l0_taken=0;
    uint32_t got_lev=0;
    for(uint32_t face=0;face<faces;face++){
        uint32_t srcoff=face*face_stride;
        uint32_t lw=w, lh=h, ld=depth, lev=0;
        for(;lev<nmip;lev++){
            uint32_t plane=tex_level_bytes(fmt,lw,lh,1,pitch);
            int failed=0;
            for(uint32_t z=0;z<ld;z++){
                g_dptexdec++;
                if(!tex_decode_level(g_base+ea+srcoff+z*plane,g_texscratch,
                                     fmt,lw,lh,pitch)){
                    { static uint32_t seenf[32]; static int nf2;
                      int f3=0; for(int i2=0;i2<nf2;i2++) if(seenf[i2]==fmt) f3=1;
                      if(!f3&&nf2<32){ seenf[nf2++]=fmt;
                        fprintf(stderr,"[RSXD] texture decode FAILED fmt=0x%02x "
                                "%ux%u pitch=%u ea=0x%x - unit falls back to "
                                "white\n",fmt,lw,lh,pitch,ea); } }
                    failed=1; break; }
                if(!l0_taken){
                    l0_taken=1;
                    for(uint32_t i2=0;i2<lw*lh;i2++){ uint32_t px=g_texscratch[i2];
                        l0sum+=(px&0xff)+((px>>8)&0xff)+((px>>16)&0xff); }
                    static int tdump=-1; static long tdn;
                    if(tdump<0) tdump=getenv("PS3_RSX_TEXDUMP")?1:0;
                    if(tdump&&tdn<128){ tdn++;
                        char pth[80];
                        snprintf(pth,sizeof pth,"out/tex_%x_%ux%u.bmp",ea,lw,lh);
                        write_bmp(pth,g_texscratch,lw,lh);
                        snprintf(pth,sizeof pth,"out/texraw_%x_%ux%u_f%02x.bin",
                                 ea,lw,lh,fmt&0xff);
                        FILE* rf=fopen(pth,"wb");
                        if(rf){ uint32_t tot=tex_total_bytes(fmt,w,h,depth,nmip,
                                   type==FP_TEX_CUBE,pitch);
                            fwrite(g_base+ea,1,tot,rf); fclose(rf); } }
                }
                { static int tdm=-2; static long tdmn;
                  if(tdm==-2){ const char* e=getenv("PS3_RSX_TEXDUMPMIPS");
                               tdm=e?atoi(e):0; if(e&&!tdm) tdm=1; }
                  if(tdm>0&&!face&&!z&&w>=(uint32_t)tdm&&tdmn<512){ tdmn++;
                    char pth[80];
                    snprintf(pth,sizeof pth,"out/texm_%x_L%02u_%ux%u.bmp",
                             ea,lev,lw,lh);
                    write_bmp(pth,g_texscratch,lw,lh); } }
                uint32_t ln=lw*lh*4;
                if(g_toff+ln>g_tend){
                    if(ln>TBUF_CAP){ static int wn4; if(wn4++<8)
                        fprintf(stderr,"[RSXD] texture level %ux%u exceeds the "
                                "staging buffer\n",lw,lh);
                        failed=1; break; }
                    cmd_submit(); g_toff=0; cmd_begin();
                }
                tstage_settle();
                memcpy(g_tptr+g_toff,g_texscratch,ln); g_tstaged=1;
                VkBufferImageCopy lb={.bufferOffset=g_toff,
                    .imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,lev,
                        (type==FP_TEX_CUBE)?face:0u,1},
                    .imageOffset={0,0,(type==FP_TEX_3D)?(int32_t)z:0},
                    .imageExtent={lw,lh,1}};
                vkCmdCopyBufferToImage(g_cmd,g_tbuf,x->img,
                    VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&lb);
                g_toff+=ln;
            }
            if(failed) break;
            srcoff+=tex_level_bytes(fmt,lw,lh,ld,pitch);
            if(lw>1) lw>>=1; if(lh>1) lh>>=1; if(ld>1) ld>>=1;
        }
        if(!lev){
            static int wn3; if(wn3++<16)
                fprintf(stderr,"[RSXD] texture fmt 0x%02x %ux%u UNSUPPORTED - "
                        "grep gcm_enum.h\n",fmt,w,h);
            return 0;
        }
        if(!face||lev<got_lev) got_lev=lev;
    }
    x->nmip=got_lev;
    x->type=(uint8_t)type; x->depth=depth;
    b.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    b.dstAccessMask=VK_ACCESS_SHADER_READ_BIT;
    b.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    b.newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    tex_unlink(x);
    x->ea=ea; x->fmt=fmtw; x->rect=t->image_rect; x->ctl3=t->control3;
    x->qhash=qh; x->ready=1; x->last_frame=x->use_frame=g_frame;
    x->use_drain=g_tex_drain;
    tex_link(x);
    { static long nt; if(++nt<=400){
        uint32_t avg=(uint32_t)(l0sum/((uint64_t)w*h*3));
        fprintf(stderr,"[RSXD] tex #%ld u%u fmt=0x%02x %ux%u mips=%u/%u pitch=%u "
                "%s%s%s remap=0x%x ea=0x%x avg=%u\n",
                nt,unit,fmt,w,h,x->nmip,(fmtw>>16)&0xff,pitch,
                GCM_TEX_LN(fmt)?"LN":"SZ",
                type==FP_TEX_CUBE?" CUBE(6 faces)":"",
                type==FP_TEX_3D?" 3D":"",t->control1,ea,avg);
        if(type==FP_TEX_CUBE)
            fprintf(stderr,"[RSXD]   cube face stride %u bytes (+X,-X,+Y,-Y,"
                    "+Z,-Z)\n",cube_face_stride(fmt,w,h,nmip,pitch));
        if(type==FP_TEX_3D)
            fprintf(stderr,"[RSXD]   3D depth %u\n",depth);
        if(avg<=2){ const uint8_t* rp=g_base+ea;
            fprintf(stderr,"[RSXD]   src:");
            for(int k2=0;k2<32;k2++) fprintf(stderr,"%s%02x",(k2&3)?"":" ",rp[k2]);
            fprintf(stderr,"\n"); } } }
    return x;
}

typedef struct {
    uint32_t ea, fmt, rect, pitch, qhash;
    VkImage img; VkDeviceMemory mem; VkImageView view;
    uint64_t last_frame, use_frame; int ready; uint32_t w,h;
} VTex;
#define NVTEX 64
static VTex g_vtex[NVTEX];

static VkImageView vtex_get(uint32_t unit){
    { static int vw=-1; if(vw<0) vw=getenv("PS3_RSX_VTEXWHITE")?1:0;
      if(vw) return 0; }
    RsxTexture* t=&g_rsx.vtex[unit&3];
    uint32_t fmtw=t->format;
    uint32_t loc=(fmtw&3)-1;
    uint32_t fmt=(fmtw>>8)&0xff;
    uint32_t w=(t->image_rect>>16)&0xffff, h=t->image_rect&0xffff;
    uint32_t pitch=t->control3&0xfffff;
    if(!w||!h||w>4096||h>4096){ static int wn0; if(wn0++<16)
        fprintf(stderr,"[RSXD] tex u%u bad rect %ux%u (ctl0=0x%x fmt=0x%x)\n",
                unit,w,h,t->control0,fmtw);
        return 0; }
    uint32_t base_fmt=fmt&0x9f;
    if(base_fmt!=0x9b&&base_fmt!=0x9c){
        static int wn; if(wn++<8)
            fprintf(stderr,"[RSXD] vertex texture fmt 0x%02x unexpected (SDK: only "
                    "W32Z32Y32X32F/X32F) - skip\n",fmt);
        return 0;
    }
    uint32_t ea=resolve(t->offset,loc);
    if(!ea) return 0;
    { VkImageView rv=rt_as_tex(ea,w,h);
      if(rv){ static long an; if(++an<=16)
          fprintf(stderr,"[RSXD] vtex u%u aliases RT 0x%x %ux%u\n",unit,ea,w,h);
          return rv; } }
    uint32_t bpp=(base_fmt==0x9b)?16:4;
    if(!pitch) pitch=w*bpp;
    uint32_t bytes=h*pitch;
    uint32_t qh=tex_qhash(ea,bytes);
    VTex* x=0;
    for(int i=0;i<NVTEX;i++){
        VTex* c2=&g_vtex[i];
        if(c2->ready&&c2->ea==ea&&c2->fmt==fmtw&&c2->rect==t->image_rect&&
           c2->pitch==pitch){
            if(c2->qhash==qh){ c2->last_frame=c2->use_frame=g_frame;
                               return c2->view; }
            x=c2; break;
        }
    }
    if(!x){
        x=0;
        for(int i=0;i<NVTEX;i++){
            if(!g_vtex[i].img){ x=&g_vtex[i]; break; }
            if(g_vtex[i].use_frame==g_frame) continue;
            if(!x||g_vtex[i].last_frame<x->last_frame) x=&g_vtex[i];
        }
        if(!x){ static int wnv; if(wnv++<8)
            fprintf(stderr,"[RSXD] vertex-texture cache full this frame "
                    "(>%d live) - bump NVTEX\n",NVTEX);
            return 0; }
        if(x->img&&(x->w!=w||x->h!=h)){
            cmd_submit();
            vkDestroyImageView(g_dev,x->view,NULL); vkDestroyImage(g_dev,x->img,NULL);
            vkFreeMemory(g_dev,x->mem,NULL); memset(x,0,sizeof *x);
        }
        if(!x->img){
            if(!make_img(w,h,VK_FORMAT_R32G32B32A32_SFLOAT,
                VK_IMAGE_USAGE_SAMPLED_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT,
                VK_IMAGE_ASPECT_COLOR_BIT,&x->img,&x->mem,&x->view)) return 0;
            x->w=w; x->h=h; x->ready=0;
        }
    }
    g_toff=(g_toff+15u)&~15u;
    uint32_t need=w*h*16;
    if(g_toff+need>g_tend){
        cmd_submit(); g_toff=0;
        if(need>TBUF_CAP){ static int wn2; if(wn2++<8)
            fprintf(stderr,"[RSXD] vtex %ux%u exceeds the staging buffer\n",w,h);
            return 0; }
    }
    tstage_settle();
    float* dst=(float*)(g_tptr+g_toff); g_tstaged=1;
    for(uint32_t y=0;y<h;y++) for(uint32_t x2=0;x2<w;x2++){
        const uint8_t* pxl=g_base+ea+y*pitch+x2*bpp;
        float* o=dst+(y*w+x2)*4;
        if(base_fmt==0x9b){
            for(int k=0;k<4;k++){
                uint32_t u=((uint32_t)pxl[k*4]<<24)|(pxl[k*4+1]<<16)|
                           (pxl[k*4+2]<<8)|pxl[k*4+3];
                memcpy(&o[k],&u,4);
            }
        } else {
            uint32_t u=((uint32_t)pxl[0]<<24)|(pxl[1]<<16)|(pxl[2]<<8)|pxl[3];
            memcpy(&o[0],&u,4); o[1]=0; o[2]=0; o[3]=1;
        }
    }
    rp_end(); cmd_begin();
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=x->ready?VK_ACCESS_SHADER_READ_BIT:0,
        .dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
        .oldLayout=x->ready?VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                           :VK_IMAGE_LAYOUT_UNDEFINED,
        .newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=x->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    VkBufferImageCopy bic={.bufferOffset=g_toff,
        .imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},.imageExtent={w,h,1}};
    vkCmdCopyBufferToImage(g_cmd,g_tbuf,x->img,
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&bic);
    b.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    b.dstAccessMask=VK_ACCESS_SHADER_READ_BIT;
    b.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    b.newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    g_toff+=need;
    x->ea=ea; x->fmt=fmtw; x->rect=t->image_rect; x->pitch=pitch;
    x->qhash=qh; x->ready=1; x->last_frame=x->use_frame=g_frame;
    { static long nv2; if(++nv2<=64){
        float lo2=dst[0],hi2=dst[0]; double sum=0;
        for(uint32_t i2=0;i2<w*h;i2++){ float v=dst[i2*4];
            if(v<lo2)lo2=v; if(v>hi2)hi2=v; sum+=v; }
        fprintf(stderr,"[RSXD] vtex x[]: min=%g max=%g avg=%g\n",
                lo2,hi2,sum/(double)(w*h)); } }
    { static long nv2; if(++nv2<=64)
        fprintf(stderr,"[RSXD] vtex #%ld u%u fmt=0x%02x %ux%u pitch=%u ea=0x%x\n",
                nv2,unit,fmt,w,h,pitch,ea); }
    return x->view;
}

static float half2f(uint16_t h){
    uint32_t s=(h>>15)&1,e=(h>>10)&0x1f,f=h&0x3ff,bits;
    if(e==0){ if(!f) bits=s<<31;
        else { e=127-14; while(!(f&0x400)){ f<<=1; e--; } f&=0x3ff;
               bits=(s<<31)|(e<<23)|(f<<13); } }
    else if(e==31) bits=(s<<31)|0x7f800000|(f<<13);
    else bits=(s<<31)|((e-15+127)<<23)|(f<<13);
    float r; memcpy(&r,&bits,4); return r;
}
static void decode_attr_bytes(const uint8_t* p, uint32_t type, uint32_t size,
                              float out[4]){
    switch(type){
    case 1:
        for(uint32_t k2=0;k2<size;k2++){
            int16_t v=(int16_t)((p[k2*2]<<8)|p[k2*2+1]);
            out[k2]=(float)v/32767.0f; }
        break;
    case 2:
        for(uint32_t k2=0;k2<size;k2++){
            uint32_t u=((uint32_t)p[k2*4]<<24)|((uint32_t)p[k2*4+1]<<16)|
                       ((uint32_t)p[k2*4+2]<<8)|p[k2*4+3];
            float f; memcpy(&f,&u,4); out[k2]=f; }
        break;
    case 3:
        for(uint32_t k2=0;k2<size;k2++){
            uint16_t hv=(uint16_t)((p[k2*2]<<8)|p[k2*2+1]);
            out[k2]=half2f(hv); }
        break;
    case 4:
        for(uint32_t k2=0;k2<size;k2++) out[k2]=(float)p[k2]/255.0f;
        break;
    case 5:
        for(uint32_t k2=0;k2<size;k2++){
            int16_t v=(int16_t)((p[k2*2]<<8)|p[k2*2+1]);
            out[k2]=(float)v; }
        break;
    case 6:{
        uint32_t u=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
                   ((uint32_t)p[2]<<8)|p[3];
        int32_t x=(int32_t)(u<<21)>>21, y=(int32_t)(u<<10)>>21, z=(int32_t)u>>22;
        out[0]=(float)x/1023.0f; out[1]=(float)y/1023.0f; out[2]=(float)z/511.0f;
        break; }
    case 7:
        for(uint32_t k2=0;k2<size;k2++) out[k2]=(float)p[k2];
        break;
    default:
        { static int wn; if(wn++<8) fprintf(stderr,"[RSXD] vertex type %u?\n",type); }
        break;
    }
}

static uint32_t attr_bytes(uint32_t type, uint32_t size){
    switch(type){
    case 1: case 3: case 5: return size*2;
    case 2: return size*4;
    case 4: case 7: return size;
    case 6: return 4;
    default: return 0;
    }
}

static const uint8_t* g_inl_bytes;
static uint32_t g_inl_stride, g_inl_attr_off[16];

typedef struct {
    int      kind;
    float    konst[4];
    const uint8_t* base;
    const uint8_t* limit;
    uint32_t stride, type, size, abytes;
    uint32_t freq; int modulo;
    int      native;
    uint32_t dststride;
    uint32_t swap;
} AttrFetch;

static int attr_fetch_begin(uint32_t a, AttrFetch* f){
    memset(f,0,sizeof *f);
    uint32_t fmt=g_rsx.vtx[a].format;
    f->type=fmt&0xf; f->size=(fmt>>4)&0xf; f->stride=(fmt>>8)&0xff;
    if(f->size>4){ static int wn; if(wn++<8)
        fprintf(stderr,"[RSXD] attr %u format 0x%08x has size %u (GCM allows "
                "1..4) - clamped\n",a,fmt,f->size);
        f->size=4; }
    if(!f->size||!f->type){
        f->kind=0;
        f->native=0; f->dststride=16; f->swap=1;
        for(int k=0;k<4;k++){ uint32_t u=g_rsx.imm4f[a][k];
            memcpy(&f->konst[k],&u,4); }
        return 1;
    }
    f->abytes=attr_bytes(f->type,f->size);
    { VkFormat nf; uint32_t nstride; int nat=0;
      attr_layout(a,&nf,&nstride,&nat);
      f->native=nat;
      f->dststride=nat?nstride:16u;
      f->swap=nat?((f->type==2)?4u:(f->type==1||f->type==3)?2u:1u):1u; }
    if(g_inl_bytes){
        f->kind=1; f->base=g_inl_bytes+g_inl_attr_off[a]; f->stride=g_inl_stride;
        return 1;
    }
    f->kind=2;
    f->freq=(fmt>>16)&0xffff;
    f->modulo=(g_rsx.freq_div_op>>a)&1;
    uint32_t off=g_rsx.vtx[a].offset;
    uint32_t loc=(off>>31)&1;
    uint32_t ea=resolve((off&0x7fffffff)+g_rsx.vtx_base_off,loc);
    if(!ea){ static int wn; if(wn++<16)
        fprintf(stderr,"[RSXD] attr %u offset 0x%x loc=%u does not resolve - "
                "reading zeros\n",a,off,loc);
        return 0; }
    f->base=g_base+ea;
    f->limit=guest_limit(ea,loc);
    return 1;
}
static void attr_fetch_one(const AttrFetch* f, uint32_t vi, float out[4]){
    out[0]=0; out[1]=0; out[2]=0; out[3]=1;
    if(f->kind==0){ memcpy(out,f->konst,16); return; }
    if(f->freq) vi = f->modulo ? vi%f->freq : vi/f->freq;
    const uint8_t* p=f->base+(size_t)vi*f->stride;
    if(f->limit&&p+f->abytes>f->limit){
        static int wn2; if(wn2++<16)
            fprintf(stderr,"[RSXD] attr read past local memory (vi=%u stride=%u)\n",
                    vi,f->stride);
        return;
    }
    decode_attr_bytes(p,f->type,f->size,out);
}
static void attr_fetch_one_native(const AttrFetch* f, uint32_t vi, uint8_t* out){
    if(f->freq) vi = f->modulo ? vi%f->freq : vi/f->freq;
    const uint8_t* p=f->base+(size_t)vi*f->stride;
    uint32_t n=f->abytes;
    if(f->limit&&p+n>f->limit){
        static int wn3; if(wn3++<16)
            fprintf(stderr,"[RSXD] attr read past guest memory (vi=%u stride=%u)\n",
                    vi,f->stride);
        memset(out,0,n); return;
    }
    switch(f->swap){
    case 4: for(uint32_t i=0;i<n;i+=4){ out[i]=p[i+3]; out[i+1]=p[i+2];
                                        out[i+2]=p[i+1]; out[i+3]=p[i]; } break;
    case 2: for(uint32_t i=0;i<n;i+=2){ out[i]=p[i+1]; out[i+1]=p[i]; } break;
    default: memcpy(out,p,n); break;
    }
}
static void attr_fetch_native_run(const AttrFetch* f, const uint32_t* vord, uint32_t nv,
                                  uint32_t vmax, uint8_t* dst){
    uint32_t n=f->abytes, ds=f->dststride, freq=f->freq;
    uint32_t top=vmax;
    if(freq) top=f->modulo?(vmax<freq-1?vmax:freq-1):vmax/freq;
    if(n!=ds||(f->limit&&f->base+(size_t)top*f->stride+n>f->limit)){
        for(uint32_t k=0;k<nv;k++) attr_fetch_one_native(f,vord[k],dst+(size_t)k*ds);
        return;
    }
    const uint8_t* base=f->base; uint32_t stride=f->stride;
    for(uint32_t k=0;k<nv;k++){
        uint32_t vi=vord[k];
        if(freq) vi=f->modulo?vi%freq:vi/freq;
        const uint8_t* p=base+(size_t)vi*stride;
        uint8_t* o=dst+(size_t)k*ds;
        if(f->swap==4){
            for(uint32_t i=0;i<n;i+=4){ uint32_t w; memcpy(&w,p+i,4);
                w=__builtin_bswap32(w); memcpy(o+i,&w,4); }
        } else if(f->swap==2){
            uint32_t i=0;
            for(;i+4<=n;i+=4){ uint32_t w; memcpy(&w,p+i,4);
                w=((w&0x00ff00ffu)<<8)|((w>>8)&0x00ff00ffu); memcpy(o+i,&w,4); }
            if(i<n){ uint16_t s; memcpy(&s,p+i,2); s=__builtin_bswap16(s); memcpy(o+i,&s,2); }
        } else memcpy(o,p,n);
    }
}

static void staged_vertex(uint32_t a, uint32_t vi, float out[4]){
    out[0]=0; out[1]=0; out[2]=0; out[3]=1;
    AttrFetch af;
    if(attr_fetch_begin(a,&af)) attr_fetch_one(&af,vi,out);
}

void rsxd_begin(uint32_t prim){
    g_prim=prim; g_narr=0; g_nidx=0; g_ninline=0;
}
void rsxd_draw_arrays(uint32_t arg){
    if(g_narr<256){ g_arr[g_narr].first=arg&0xffffff; g_arr[g_narr].count=(arg>>24)+1; g_narr++; }
    else { static int wn; if(wn++<8)
        fprintf(stderr,"[RSXD] DRAW_ARRAYS: more than 256 ranges in one batch - "
                "the rest are dropped\n"); }
}
void rsxd_draw_index(uint32_t arg){
    if(g_nidx<4096){ g_idx[g_nidx].first=arg&0xffffff; g_idx[g_nidx].count=(arg>>24)+1; g_nidx++; }
    else { static int wn; if(wn++<8)
        fprintf(stderr,"[RSXD] DRAW_INDEX_ARRAY: more than 4096 ranges in one "
                "batch - the rest are dropped\n"); }
}
void rsxd_inline_word(uint32_t arg){
    if(g_ninline<65536) g_inline[g_ninline++]=arg;
    else { static int wn; if(wn++<8)
        fprintf(stderr,"[RSXD] INLINE_ARRAY: more than 65536 words in one batch "
                "- the rest are dropped\n"); }
}

static uint32_t expand_prim(uint32_t prim, const uint32_t* in, uint32_t n,
                            uint32_t* out, uint32_t cap){
    uint32_t k=0;
    if(prim!=8&&prim!=9&&prim!=10){
        for(uint32_t i=0;i<n&&k<cap;i++) out[k++]=in[i];
        return k;
    }
    for(uint32_t s=0;s<n;){
        while(s<n&&in[s]==0xffffffffu) s++;
        uint32_t e=s;
        while(e<n&&in[e]!=0xffffffffu) e++;
        const uint32_t* r=in+s; uint32_t m=e-s;
        switch(prim){
        case 8:
            for(uint32_t i=0;i+3<m&&k+6<=cap;i+=4){
                out[k++]=r[i]; out[k++]=r[i+1]; out[k++]=r[i+2];
                out[k++]=r[i]; out[k++]=r[i+2]; out[k++]=r[i+3]; }
            break;
        case 9:
            for(uint32_t i=0;i+3<m&&k+6<=cap;i+=2){
                out[k++]=r[i]; out[k++]=r[i+1]; out[k++]=r[i+3];
                out[k++]=r[i]; out[k++]=r[i+3]; out[k++]=r[i+2]; }
            break;
        case 10:
            for(uint32_t i=1;i+1<m&&k+3<=cap;i++){
                out[k++]=r[0]; out[k++]=r[i]; out[k++]=r[i+1]; }
            break;
        }
        s=e;
    }
    return k;
}

static uint32_t* g_tmp_idx; static uint32_t g_tmp_cap;
static uint32_t* tmp_idx(uint32_t need){
    if(need>g_tmp_cap){
        uint32_t want=need*2;
        uint32_t* p=realloc(g_tmp_idx,(size_t)want*4);
        if(!p) return 0;
        g_tmp_idx=p; g_tmp_cap=want;
    }
    return g_tmp_idx;
}

#include "vk_xfer.inc"
#include "vk_dres.inc"

void rsxd_m2m(void){  DP_T0(t); g_fp_epoch++; rsxd_m2m_inner(); DP_T1(DP_XFER,t); }
void rsxd_blit(void){ DP_T0(t); rsxd_blit_inner(); DP_T1(DP_XFER,t); }

static void ring_flush(void){
    static long n; if(n++<16)
        fprintf(stderr,"[RSXD] draw ring full mid-frame - draining to rewind "
                "(frame %llu; v=%u/%u i=%u/%u u=%u/%u)\n",
                (unsigned long long)g_frame,g_voff,g_vend,g_ioff,g_iend,
                g_uoff,g_uend);
    cmd_submit();
    uint32_t vseg=VBUF_CAP/NFRAME, iseg=IBUF_CAP/NFRAME, useg=UBUF_CAP/NFRAME;
    g_voff=(uint32_t)g_fslot*vseg; g_vend=g_voff+vseg;
    g_ioff=(uint32_t)g_fslot*iseg; g_iend=g_ioff+iseg;
    g_uoff=(uint32_t)g_fslot*useg; g_uend=g_uoff+useg;
    vkResetDescriptorPool(g_dev,g_dpool,0);
    g_vpc_valid=0; dset_cache_drop();
}

void rsxd_end(void){
    uint32_t prim=g_prim; g_prim=0;
    if(!g_narr&&!g_nidx&&!g_ninline) return;
    if(!draw_up()) return;
    static uint8_t inl_buf[65536*4];
    g_inl_bytes=0;
    if(g_ninline&&!g_narr&&!g_nidx){
        for(uint32_t i=0;i<g_ninline;i++){ uint32_t w2=g_inline[i];
            inl_buf[i*4+0]=(uint8_t)(w2>>24); inl_buf[i*4+1]=(uint8_t)(w2>>16);
            inl_buf[i*4+2]=(uint8_t)(w2>>8);  inl_buf[i*4+3]=(uint8_t)w2; }
        uint32_t stride=0;
        for(uint32_t a=0;a<16;a++){
            uint32_t fmt=g_rsx.vtx[a].format;
            uint32_t type=fmt&0xf, size=(fmt>>4)&0xf;
            g_inl_attr_off[a]=stride;
            if(type&&size) stride+=(attr_bytes(type,size)+3)&~3u;
        }
        if(stride){
            uint32_t nvi=g_ninline*4/stride;
            if(nvi){
                g_inl_bytes=inl_buf; g_inl_stride=stride;
                if(g_narr<256){ g_arr[0].first=0; g_arr[0].count=nvi; g_narr=1; }
                { static long in2; if(++in2<=8)
                    fprintf(stderr,"[RSXD] inline draw: %u words stride=%u nv=%u\n",
                            g_ninline,stride,nvi); }
            }
        }
        g_ninline=0;
    } else g_ninline=0;
    if(!g_narr&&!g_nidx) return;

    Surf* rt=current_rt();
    if(!rt) return;
    if(g_rsx.depth_mask) rt->zfloat=(g_rsx.control0>>12)&1;
    static uint64_t bypass_frame=~0ull; static uint32_t bypass_rt;
    { static int dof=-1; if(dof<0) dof=getenv("PS3_RSX_DOF")?1:0;
      if(!dof&&prim==8&&rt->ea==0x22870000){
          uint32_t l0=(g_rsx.tex[0].format&3)?((g_rsx.tex[0].format&3)-1):0;
          uint32_t tea0=resolve(g_rsx.tex[0].offset,l0);
          if(tea0==0x23240000||tea0==0x23170000){
              bypass_frame=g_frame; bypass_rt=rt->ea; return; }
          if(bypass_frame==g_frame&&bypass_rt==rt->ea&&g_rsx.blend_enable&&
             (g_rsx.blend_sfactor&0xffff)==0x0304  &&
             (g_rsx.blend_dfactor&0xffff)==0x0001  &&
             ((g_rsx.tex[0].image_rect>>16)&0xffff)==rt->w&&
             (g_rsx.tex[0].image_rect&0xffff)==rt->h){
              bypass_frame=~0ull; return; }
      } }
    int fps_zero=0;
    { static int armed=-1;
      if(armed<0) armed=getenv("PS3_RSX_FPSKIP")?1:0;
      if(armed){
      static uint32_t fps_h[16]; static int fps_n=0, poll=0;
      if(!poll--){ poll=256; fps_n=0;
          FILE* f=fopen("fpskip.on","rb");
          if(f){ char buf[256]; size_t r=fread(buf,1,255,f); buf[r]=0; fclose(f);
              const char* e=buf;
              while(*e&&fps_n<16){
                  char* end; uint32_t v=(uint32_t)strtoul(e,&end,16);
                  if(end==e){ e++; continue; }
                  fps_h[fps_n++]=v; e=end;
              } } }
      if(fps_n&&fetch_fp()){ uint32_t h=(uint32_t)g_fp_khash;
          for(int i2=0;i2<fps_n;i2++) if(fps_h[i2]==h){ fps_zero=1; break; } }
      } }
    if(prim==1){
        static uint32_t pseen[8]; static int nps;
        int f5=0; for(int i5=0;i5<nps;i5++) if(pseen[i5]==g_rsx.point_sprite) f5=1;
        if(!f5&&nps<8){ pseen[nps++]=g_rsx.point_sprite;
            fprintf(stderr,"[RSXD] POINT draw: sprite=0x%08x (en=%u rmode=%u "
                    "tex=0x%03x) point_size=0x%08x params_en=%u "
                    "outmask=0x%06x(psiz=%u) rt=0x%x\n",
                    g_rsx.point_sprite,g_rsx.point_sprite&1,
                    (g_rsx.point_sprite>>1)&3,(g_rsx.point_sprite>>8)&0x3ff,
                    g_rsx.point_size_u32,g_rsx.point_params_en,
                    g_rsx.vp_out_mask,(g_rsx.vp_out_mask>>5)&1,rt->ea); }
    }
    uint32_t used=0, texu=0, vtexu=0, nfpc=0;
    VkPipeline pipe=pipe_get(prim,0,rt->isf,&used,&texu,&vtexu,&nfpc);
    if(!pipe) return;
    DP_T0(t_tex);
    VkImageView vtview[4];
    for(int u=0;u<4;u++) vtview[u]=g_white_view;
    for(uint32_t u=0;u<4;u++) if(vtexu&(1u<<u)){
        VkImageView v=vtex_get(u);
        if(v) vtview[u]=v;
    }
    VkImageView tview[16]; VkSampler tsamp[16];
    for(int u=0;u<16;u++){ tview[u]=white_view_for(tex_target((uint32_t)u));
                           tsamp[u]=g_sampler; }
    static int tdbg=-1;
    if(tdbg<0) { const char* e=getenv("PS3_RSX_TEXDBG"); tdbg=e?atoi(e):0; }
    char tkind[17]; for(int i2=0;i2<17;i2++) tkind[i2]=0;
    static uint32_t whiteu=0xffffffffu;
    if(whiteu==0xffffffffu){ const char* e=getenv("PS3_RSX_WHITEU");
        whiteu=e?(uint32_t)strtoul(e,NULL,16):0u; }
    for(uint32_t u=0;u<16;u++) if((texu&(1u<<u))&&!(whiteu&(1u<<u))){
        RsxTexture* t=&g_rsx.tex[u];
        tkind[u]='w';
        if(t->control0>>31){
            uint32_t loc=(t->format&3)-1;
            uint32_t tea=resolve(t->offset,loc);
            uint32_t tw=(t->image_rect>>16)&0xffff, th=t->image_rect&0xffff;
            uint32_t zf=tex_zfunc(u);
            VkImageView rv=tea?depth_as_tex(tea,tw,th,(t->format>>8)&0xff,zf):0;
            if(rv){ tview[u]=rv; tsamp[u]=sampler_get(u,1,zf!=0); tkind[u]='Z'; continue; }
            rv=tea?rt_as_tex(tea,tw,th):0;
            if(rv){ tview[u]=rv; tsamp[u]=sampler_get(u,1,0); tkind[u]='R'; continue; }
        }
        Tex* tx=tex_get(u);
        if(tx){ tview[u]=tx->view; tsamp[u]=sampler_get(u,tx->nmip,0); tkind[u]='T'; }
        else {
            RsxTexture* t3=&g_rsx.tex[u];
            uint32_t l3=(t3->format&3)?((t3->format&3)-1):0;
            uint32_t e3=resolve(t3->offset,l3);
            static struct { uint32_t ea,fmt,rect; } wseen[64]; static int nws;
            int f4=0;
            for(int i3=0;i3<nws;i3++)
                if(wseen[i3].ea==e3&&wseen[i3].fmt==t3->format&&
                   wseen[i3].rect==t3->image_rect){ f4=1; break; }
            if(!f4&&nws<64){
                wseen[nws].ea=e3; wseen[nws].fmt=t3->format;
                wseen[nws].rect=t3->image_rect; nws++;
                fprintf(stderr,"[RSXD] WHITE FALLBACK u%u ea=0x%x fmt=0x%02x "
                        "(word 0x%08x) %ux%u ctl0=0x%08x ctl3=0x%08x rt=0x%x\n",
                        u,e3,(t3->format>>8)&0xff,t3->format,
                        (t3->image_rect>>16)&0xffff,t3->image_rect&0xffff,
                        t3->control0,t3->control3,rt->ea);
            }
        }
    }
    DP_T1(DP_TEX,t_tex);
    if(tdbg==2){
        static long tv; if(tv++<40000){
            fprintf(stderr,"[TEXDBG2] rt=0x%x(%ux%u) ct=%x prim=%u nfq=%u bl=%u(%x/%x) "
                    "cm=%x z=%u/%x/%u fpc=%x at=%u/%x/%02x fp=%08x",
                    rt->ea,rt->w,rt->h,g_rsx.color_target,prim,
                    g_nidx?g_idx[0].count:(g_narr?g_arr[0].count:0),
                    g_rsx.blend_enable,g_rsx.blend_sfactor,g_rsx.blend_dfactor,
                    g_rsx.color_mask,g_rsx.depth_test,g_rsx.depth_func,
                    g_rsx.depth_mask,g_rsx.fp_control,
                    g_rsx.alpha_test,g_rsx.alpha_test?g_rsx.alpha_func:0,
                    g_rsx.alpha_test?g_rsx.alpha_ref:0,
                    (uint32_t)fnv1a(g_fp_words,g_fp_nwords*4,0xcbf29ce484222325ull));
            for(uint32_t u=0;u<16;u++) if(texu&(1u<<u)){
                RsxTexture* t2=&g_rsx.tex[u];
                uint32_t l2=(t2->format&3)-1;
                fprintf(stderr," u%u:%c:0x%x:%ux%u",u,tkind[u]?tkind[u]:'?',
                        resolve(t2->offset,l2),
                        (t2->image_rect>>16)&0xffff,t2->image_rect&0xffff);
            }
            fprintf(stderr,"\n"); } }
    if(tdbg){ static long tn; if(tn++<20000){
        fprintf(stderr,"[TEXDBG] rt=0x%x texu=0x%x kinds=",rt->ea,texu);
        for(int u=0;u<16;u++) fprintf(stderr,"%c",tkind[u]?tkind[u]:'.');
        fprintf(stderr,"\n"); } }
    { static int klog=-1; if(klog<0) klog=rsxd_diag_on("PS3_RSX_KINDLOG","PS3_RSX_NOKINDLOG");
      if(klog){
        static struct { uint32_t ea, rect; char kind; } seen[256]; static int nseen;
        static int nlogged;
        for(uint32_t u=0;u<16&&nlogged<200;u++){
            if(!(texu&(1u<<u))||!tkind[u]) continue;
            RsxTexture* t2=&g_rsx.tex[u];
            uint32_t l2=(t2->format&3)?((t2->format&3)-1):0;
            uint32_t e2=resolve(t2->offset,l2);
            if(!e2) continue;
            int i2=0;
            for(;i2<nseen;i2++)
                if(seen[i2].ea==e2&&seen[i2].rect==t2->image_rect) break;
            if(i2==nseen){ if(nseen<256){ seen[nseen].ea=e2;
                                          seen[nseen].rect=t2->image_rect;
                                          seen[nseen].kind=tkind[u]; nseen++; }
                           continue; }
            if(seen[i2].kind==tkind[u]) continue;
            fprintf(stderr,"[RSXD] tex 0x%x binding flipped %c -> %c "
                    "(frame %llu, rt=0x%x u%u %ux%u)\n",e2,seen[i2].kind,
                    tkind[u],(unsigned long long)g_frame,rt->ea,u,
                    (t2->image_rect>>16)&0xffff,t2->image_rect&0xffff);
            seen[i2].kind=tkind[u]; nlogged++;
        }
      } }
    DP_T0(t_hash);
    { static int fpall=-1; if(fpall<0) fpall=rsxd_diag_on("PS3_RSX_FPALL","PS3_RSX_NOFPALL");
      if(fpall){
        static uint32_t seen[256]; static int nseen;
        static uint64_t era=~0ull;
        uint32_t fh=(uint32_t)g_fp_khash;
        static struct { uint32_t ea; int n; } perrt[96]; static int nperrt;
        if(era!=g_frame/512){ era=g_frame/512; nseen=0; nperrt=0; }
        int isnew=1;
        for(int i=0;i<nseen;i++) if(seen[i]==fh){ isnew=0; break; }
        if(isnew){
            int lim=(rt->w<=64&&rt->h<=64)?4:64;
            int i=0;
            for(;i<nperrt;i++) if(perrt[i].ea==rt->ea) break;
            if(i==nperrt){ if(nperrt<96){ perrt[nperrt].ea=rt->ea;
                                          perrt[nperrt].n=0; nperrt++; }
                           else isnew=0; }
            if(isnew){ if(perrt[i].n>=lim) isnew=0; else perrt[i].n++; }
        }
        if(isnew&&nseen<256){
            seen[nseen++]=fh;
            char pth[64]; snprintf(pth,sizeof pth,"out/fpall_%08x.bin",fh);
            FILE* f=fopen(pth,"wb");
            if(f){ fwrite(g_fp_words,4,g_fp_nwords,f); fclose(f); }
            snprintf(pth,sizeof pth,"out/vpall_%08x.bin",fh);
            f=fopen(pth,"wb");
            if(f){ uint32_t s2=g_rsx.vp_start&0x1ff;
                   for(uint32_t i=s2;i<512;i++){ fwrite(g_rsx.vp_instr[i],1,16,f);
                       if(g_rsx.vp_instr[i][3]&1) break; }
                   fclose(f); }
            fprintf(stderr,"[FPALL] %08x frm=%llu rt=0x%x(%ux%u) prim=%u bl=%u(%x/%x) "
                    "cm=%x z=%u/%x/%u fpc=%x texu=0x%x",fh,
                    (unsigned long long)g_frame,rt->ea,rt->w,rt->h,prim,
                    g_rsx.blend_enable,g_rsx.blend_sfactor,g_rsx.blend_dfactor,
                    g_rsx.color_mask,g_rsx.depth_test,g_rsx.depth_func,
                    g_rsx.depth_mask,g_rsx.fp_control,texu);
            for(uint32_t u=0;u<16;u++) if(texu&(1u<<u)){
                RsxTexture* t2=&g_rsx.tex[u]; uint32_t l2=(t2->format&3)-1;
                fprintf(stderr," u%u:%c:0x%x:%ux%u:rm%x",u,tkind[u]?tkind[u]:'?',
                        resolve(t2->offset,l2),(t2->image_rect>>16)&0xffff,
                        t2->image_rect&0xffff,t2->control1);
            }
            fprintf(stderr,"\n");
        } } }
    DP_T1(DP_HASH,t_hash);

    DP_T0(t_idx);
    uint32_t total=0;
    for(int i=0;i<g_narr;i++) total+=g_arr[i].count;
    for(int i=0;i<g_nidx;i++) total+=g_idx[i].count;
    if(!total) return;
    uint32_t* raw=tmp_idx(total*4+16);
    if(!raw) return;
    uint32_t n=0;
    if(g_nidx){
        uint32_t type=(g_rsx.index_dma>>4)&0xf;
        uint32_t loc=g_rsx.index_dma&0xf;
        uint32_t iea=resolve(g_rsx.index_addr,loc);
        if(!iea) return;
        uint32_t rst = g_rsx.restart_en ? g_rsx.restart_idx
                                       : 0xffffffffu;
        uint32_t isz=(type==1)?2u:4u;
        const uint8_t* ilim=guest_limit(iea,loc);
        const uint8_t* ibas=g_base+iea;
        uint64_t maxii=(ilim>ibas)?(uint64_t)(ilim-ibas)/isz:0;
        int oob=0;
        for(int i=0;i<g_nidx&&!oob;i++)
            for(uint32_t j=0;j<g_idx[i].count;j++){
                uint32_t ii=g_idx[i].first+j;
                if((uint64_t)ii>=maxii){
                    static int wn; if(wn++<8)
                        fprintf(stderr,"[RSXD] index array 0x%x runs past guest "
                                "memory at index %u (%llu readable) - draw "
                                "truncated to %u indices\n",
                                iea,ii,(unsigned long long)maxii,n);
                    oob=1; break;
                }
                uint32_t v=(type==1)
                    ? (uint32_t)((g_base[iea+ii*2]<<8)|g_base[iea+ii*2+1])
                    : rd32(iea+ii*4);
                raw[n++]=(g_rsx.restart_en&&v==rst)?0xffffffffu
                                                   :v+g_rsx.vtx_base_idx;
            }
    } else {
        for(int i=0;i<g_narr;i++)
            for(uint32_t j=0;j<g_arr[i].count;j++)
                raw[n++]=g_arr[i].first+j;
    }
    uint32_t* fin=raw; uint32_t nf=n;
    if(prim==8||prim==9||prim==10){
        fin=raw+n;
        nf=expand_prim(prim,raw,n,fin,total*4+16-n);
    }
    if(!nf) return;

    uint32_t vmin=~0u,vmax=0;
    for(uint32_t i=0;i<nf;i++){ uint32_t v=fin[i];
        if(v==0xffffffffu) continue;
        if(v<vmin)vmin=v; if(v>vmax)vmax=v; }
    if(vmin>vmax) return;
    uint32_t nv=vmax-vmin+1;
    if(nv>1u<<20){ static int wn; if(wn++<8)
        fprintf(stderr,"[RSXD] vertex range %u too large - skip\n",nv); return; }

    static uint32_t vseen[1u<<20], vmap[1u<<20], vord[1u<<20];
    static uint32_t vgen;
    if(++vgen==0){ memset(vseen,0,sizeof vseen); vgen=1; }
    uint32_t nuniq=0;
    for(uint32_t i=0;i<nf;i++){
        uint32_t v=fin[i];
        if(v==0xffffffffu) continue;
        uint32_t o=v-vmin;
        if(vseen[o]==vgen) continue;
        vseen[o]=vgen; vmap[o]=nuniq; vord[nuniq++]=v;
    }
    if(!nuniq) return;
    DP_T1(DP_IDX,t_idx);

    {
        uint64_t vneed=0;
        for(uint32_t a=0;a<16;a++) if(used&(1u<<a)){
            VkFormat af2; uint32_t as2;
            attr_layout(a,&af2,&as2,0);
            vneed+=15u+(uint64_t)nuniq*as2;
        }
        uint64_t ineed=(uint64_t)nf*4;
        uint64_t uneed=(468u*16+g_ubo_align-1)&~(uint64_t)(g_ubo_align-1);
        if(nfpc) uneed+=(nfpc*16+g_ubo_align-1)&~(uint64_t)(g_ubo_align-1);
        if(g_voff+vneed>g_vend||g_ioff+ineed>g_iend||g_uoff+uneed>g_uend){
            uint32_t vseg=VBUF_CAP/NFRAME, iseg=IBUF_CAP/NFRAME,
                     useg=UBUF_CAP/NFRAME;
            if(vneed>vseg||ineed>iseg||uneed>useg){
                static int wn8; if(wn8++<8)
                    fprintf(stderr,"[RSXD] one draw wants %lluK vtx / %lluK idx "
                            "/ %lluK ubo - larger than the ring (%uK/%uK/%uK); "
                            "SKIPPED, raise the cap\n",
                            (unsigned long long)(vneed>>10),
                            (unsigned long long)(ineed>>10),
                            (unsigned long long)(uneed>>10),
                            vseg>>10,iseg>>10,useg>>10);
                return;
            }
            ring_flush();
        }
    }

    DP_T0(t_vf);
    uint32_t vbase_off[16];
    for(uint32_t a=0;a<16;a++) if(used&(1u<<a)){
        AttrFetch af;
        int ok=attr_fetch_begin(a,&af);
        g_voff=(g_voff+15u)&~15u;
        uint32_t need=nuniq*af.dststride;
        if(g_voff+need>g_vend){ static int wn2; if(wn2++<8)
            fprintf(stderr,"[RSXD] vertex ring full\n"); return; }
        uint8_t* dst=g_vptr+g_voff;
        if(!ok){
            memset(dst,0,(size_t)need);
        } else if(af.native){
            attr_fetch_native_run(&af,vord,nuniq,vmax,dst);
        } else {
            for(uint32_t k=0;k<nuniq;k++)
                attr_fetch_one(&af,vord[k],(float*)(dst+(size_t)k*16));
        }
        vbase_off[a]=g_voff; g_voff+=need;
        g_dpvbytes+=need; g_dpvbytes16+=(uint64_t)nuniq*16;
    }
    DP_T1(DP_VFETCH,t_vf);
    DP_T0(t_idx2);
    int i16=(nuniq<=0xffffu);
    uint32_t istride=i16?2u:4u;
    g_ioff=(g_ioff+3u)&~3u;
    if(g_ioff+nf*istride>g_iend){ static int wn3; if(wn3++<8)
        fprintf(stderr,"[RSXD] index ring full\n"); return; }
    if(i16){
        uint16_t* d16=(uint16_t*)(g_iptr+g_ioff);
        for(uint32_t i=0;i<nf;i++)
            d16[i]=(fin[i]==0xffffffffu)?0xffffu:(uint16_t)vmap[fin[i]-vmin];
    } else {
        uint32_t* idst=(uint32_t*)(g_iptr+g_ioff);
        for(uint32_t i=0;i<nf;i++)
            idst[i]=(fin[i]==0xffffffffu)?0xffffffffu:vmap[fin[i]-vmin];
    }
    uint32_t ibase=g_ioff; g_ioff+=nf*istride;
    DP_T1(DP_IDX,t_idx2);
    g_dpdraws++; g_dpverts+=nuniq; g_dptris+=nf/3; if(i16) g_dpi16++;

    DP_T0(t_ubo);
    uint32_t usz=(468*16+g_ubo_align-1)&~(g_ubo_align-1);
    int vpc_dirty=(!g_vpc_valid||g_vpc_epoch!=g_vp_const_epoch);
    if(vpc_dirty){
        if(g_uoff+usz>g_uend){ static int wn4; if(wn4++<8)
            fprintf(stderr,"[RSXD] ubo ring full\n"); return; }
        memcpy(g_uptr+g_uoff,g_rsx.vp_const,468*16);
    }
    if(g_ptbuf){
        static uint32_t visfp=0; static int vin=-1;
        if(vin<0){ const char* e=getenv("PS3_RSX_VISFP");
                   visfp=e?(uint32_t)strtoul(e,NULL,16):0; vin=1; }
        if(!visfp||visfp==(uint32_t)fnv1a(g_fp_words,g_fp_nwords*4,
                                          0xcbf29ce484222325ull)){
            FILE* f=fopen("out/pixtrace_vpc.bin","wb");
            if(f){ fwrite(g_rsx.vp_const,16,468,f); fclose(f); }
        }
    }
    uint32_t uoff;
    if(vpc_dirty){ uoff=g_uoff; g_uoff+=usz;
                   g_vpc_uoff=uoff; g_vpc_epoch=g_vp_const_epoch;
                   g_vpc_valid=1; }
    else { uoff=g_vpc_uoff; g_dpvpcskip++; }
    uint32_t fpcoff=uoff, fpcsz=16;
    if(nfpc){
        static float fpc[4096][4];
        uint32_t n=fp_consts(fpc,(uint32_t)(sizeof fpc/sizeof fpc[0]));
        if(n!=nfpc){ static int wn6; if(wn6++<8)
            fprintf(stderr,"[RSXD] fp constants: collected %u, module wants %u "
                    "- the two ucode walks disagree\n",n,nfpc); }
        if(n>nfpc) n=nfpc;
        fpcsz=(nfpc*16+g_ubo_align-1)&~(g_ubo_align-1);
        if(g_uoff+fpcsz>g_uend){ static int wn7; if(wn7++<8)
            fprintf(stderr,"[RSXD] ubo ring full (fp consts)\n"); return; }
        memcpy(g_uptr+g_uoff,fpc,n*16);
        if(n<nfpc) memset(g_uptr+g_uoff+n*16,0,(nfpc-n)*16);
        fpcoff=g_uoff; g_uoff+=fpcsz;
        fpcsz=nfpc*16;
    }
    DP_T1(DP_UBO,t_ubo);

    DP_T0(t_desc);
    VkDescriptorSet dset;
    int dset_hit=0, dset_slot=-1;
    {
        uint64_t dk=0xcbf29ce484222325ull;
        dk=fnv1a(tview,sizeof tview,dk);
        dk=fnv1a(tsamp,sizeof tsamp,dk);
        dk=fnv1a(vtview,sizeof vtview,dk);
        dk=fnv1a(&fpcsz,sizeof fpcsz,dk);
        uint32_t b=(uint32_t)dk&(NDSET-1);
        for(uint32_t p=0;p<NDSET;p++){
            uint32_t i2=(b+p)&(NDSET-1);
            DsetEnt* e=&g_dset[i2];
            if(e->gen!=g_dset_gen){ dset_slot=(int)i2; break; }
            if(e->key==dk){ dset=e->set; dset_hit=1; g_dpdsethit++; break; }
        }
        if(!dset_hit&&dset_slot>=0){
            g_dset[dset_slot].key=dk;
            g_dset[dset_slot].gen=g_dset_gen;
        }
    }
    if(!dset_hit){
    VkDescriptorSetAllocateInfo dai={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
        .descriptorPool=g_dpool,.descriptorSetCount=1,.pSetLayouts=&g_dsl};
    if(vkAllocateDescriptorSets(g_dev,&dai,&dset)){
        static int wn5; if(wn5++<8) fprintf(stderr,"[RSXD] descriptor pool exhausted\n");
        if(dset_slot>=0) g_dset[dset_slot].gen=0;
        return;
    }
    if(dset_slot>=0){ g_dset[dset_slot].set=dset; g_dset_live++; }
    { VkDescriptorBufferInfo bi={.buffer=g_ubuf,.offset=0,.range=468*16};
      VkDescriptorBufferInfo fpci={.buffer=g_ubuf,.offset=0,.range=fpcsz};
      VkDescriptorImageInfo ii[16], vi[4];
      VkWriteDescriptorSet wr[23];
      wr[0]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
          .dstSet=dset,.dstBinding=0,.descriptorCount=1,
          .descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,.pBufferInfo=&bi};
      wr[1]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
          .dstSet=dset,.dstBinding=1,.descriptorCount=1,
          .descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,.pBufferInfo=&fpci};
      for(int i=0;i<4;i++){
          vi[i]=(VkDescriptorImageInfo){.sampler=g_vsampler,.imageView=vtview[i],
              .imageLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
          wr[2+i]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
              .dstSet=dset,.dstBinding=4u+(uint32_t)i,.descriptorCount=1,
              .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,.pImageInfo=&vi[i]};
      }
      for(int i=0;i<16;i++){
          ii[i]=(VkDescriptorImageInfo){.sampler=tsamp[i],.imageView=tview[i],
              .imageLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
          wr[6+i]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
              .dstSet=dset,.dstBinding=8u+(uint32_t)i,.descriptorCount=1,
              .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,.pImageInfo=&ii[i]};
      }
      uint32_t nwr=22;
      VkDescriptorBufferInfo pti;
      if(g_ptbuf){
          pti=(VkDescriptorBufferInfo){.buffer=g_ptbuf,.offset=0,.range=VK_WHOLE_SIZE};
          wr[nwr++]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
              .dstSet=dset,.dstBinding=24,.descriptorCount=1,
              .descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,.pBufferInfo=&pti};
      }
      vkUpdateDescriptorSets(g_dev,nwr,wr,0,NULL); }
    }
    DP_T1(DP_DESC,t_desc);

    DP_T0(t_rec);
    rp_begin(rt);
    vkCmdBindPipeline(g_cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,pipe);
    { uint32_t dynoff[2]={uoff,fpcoff};
      vkCmdBindDescriptorSets(g_cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,g_playout,
                              0,1,&dset,2,dynoff); }
    { float sx=g_rsx.vp_scale[0],sy=g_rsx.vp_scale[1],sz=g_rsx.vp_scale[2];
      float ox=g_rsx.vp_offset[0],oy=g_rsx.vp_offset[1],oz=g_rsx.vp_offset[2];
      VkViewport vp={.x=ox-sx,.y=oy-sy,.width=sx*2,.height=sy*2,
                     .minDepth=oz-sz,.maxDepth=oz+sz};
      if(sx==0||sy==0){ vp.x=0; vp.y=0;
          vp.width=(float)rt->w; vp.height=(float)rt->h; vp.minDepth=0; vp.maxDepth=1; }
      { static int noflip=-1;
        if(noflip<0) noflip=getenv("PS3_RSX_NOFLIP")?1:0;
        if(noflip&&vp.height<0){ vp.y+=vp.height; vp.height=-vp.height; } }
      { static float lz[8][2]; static int nlz;
        int seen2=0;
        for(int k=0;k<nlz;k++) if(lz[k][0]==sz&&lz[k][1]==oz) seen2=1;
        if(!seen2&&nlz<8){ lz[nlz][0]=sz; lz[nlz][1]=oz; nlz++;
            fprintf(stderr,"[RSXD] viewport z map: scale.z=%g offset.z=%g -> "
                    "z_w = %g*z_ndc + %g%s (rt=0x%x %ux%u)\n",sz,oz,sz,oz,
                    (sz==1.0f&&oz==0.0f)?"  [matches Vulkan directly]"
                                        :"  [NOT reproduced - needs a shader-side transform]",
                    rt->ea,rt->w,rt->h); } }
      if(vp.minDepth<0)vp.minDepth=0; if(vp.maxDepth>1)vp.maxDepth=1;
      if(vp.minDepth>vp.maxDepth){ float t=vp.minDepth; vp.minDepth=vp.maxDepth; vp.maxDepth=t; }
      { static int dn2; if(!g_rsx.color_mask&&rt->zea&&dn2++<12)
          fprintf(stderr,"[RSXD] depth-only draw #%d rt=0x%x %ux%u zea=0x%x "
                  "nf=%u nv=%u ztest=%u zfunc=0x%x zmask=%u polyoff=%u(%g,%g)\n"
                  "          viewport x=%.1f y=%.1f w=%.1f h=%.1f z=[%.4f,%.4f]"
                  "  rsx scale=(%g,%g,%g) offset=(%g,%g,%g)  scissor=%ux%u+%u+%u"
                  "  cull=%u/%x front=%x\n",
                  dn2,rt->ea,rt->w,rt->h,rt->zea,nf,nv,
                  g_rsx.depth_test,g_rsx.depth_func,g_rsx.depth_mask,
                  g_rsx.poly_offs_fill,g_rsx.poly_offs_scale,g_rsx.poly_offs_bias,
                  vp.x,vp.y,vp.width,vp.height,vp.minDepth,vp.maxDepth,
                  sx,sy,sz,ox,oy,oz,
                  (g_rsx.scissor_h>>16)&0xffff,(g_rsx.scissor_v>>16)&0xffff,
                  g_rsx.scissor_h&0xffff,g_rsx.scissor_v&0xffff,
                  g_rsx.cull_enable,g_rsx.cull_face,g_rsx.front_face); }
      vkCmdSetViewport(g_cmd,0,1,&vp); }
    { VkRect2D sc=scissor_rect(rt);
      if(fps_zero){ sc.offset.x=0; sc.offset.y=0;
                    sc.extent.width=1; sc.extent.height=1; }
      vkCmdSetScissor(g_cmd,0,1,&sc); }
    { VkBuffer vbufs[16]; VkDeviceSize voffs[16]; uint32_t nb=0;
      for(uint32_t a=0;a<16;a++) if(used&(1u<<a)){
          vbufs[nb]=g_vbuf; voffs[nb]=vbase_off[a]; nb++; }
      if(nb) vkCmdBindVertexBuffers(g_cmd,0,nb,vbufs,voffs); }
    vkCmdBindIndexBuffer(g_cmd,g_ibuf,ibase,
                         i16?VK_INDEX_TYPE_UINT16:VK_INDEX_TYPE_UINT32);
    int qi=-1;
    if(qprobe_on()&&!g_rsx.color_mask&&rt->zea&&g_nq<NQUERY){
        qi=g_nq++;
        vkCmdBeginQuery(g_cmd,g_qpool,(uint32_t)qi,0);
    }
    vkCmdDrawIndexed(g_cmd,nf,1,0,0,0);
    if(qi>=0){ vkCmdEndQuery(g_cmd,g_qpool,(uint32_t)qi);
               g_qinfo[qi].ea=rt->ea; g_qinfo[qi].zea=rt->zea;
               g_qinfo[qi].nf=nf; g_qinfo[qi].nv=nv;
               g_qinfo[qi].zmask=g_rsx.depth_mask;
               g_qinfo[qi].zfunc=g_rsx.depth_func;
               g_qinfo[qi].serial=g_rsx.draw_serial; }
    DP_T1(DP_REC,t_rec);
    g_rsx.draw_serial++;
    { static int snapn=-2; static int sk=0;
      if(snapn==-2){ const char* e=getenv("PS3_RSX_SNAPBIG"); snapn=e?atoi(e):0; }
      static uint32_t snapea=0xffffffffu;
      if(snapea==0xffffffffu){ const char* e=getenv("PS3_RSX_SNAPEA");
                               snapea=e?(uint32_t)strtoul(e,0,16):0; }
      static int armed=0;
      static long snapfrm=-1;
      if(snapfrm<0){ const char* e=getenv("PS3_RSX_SNAPFRAME");
                     snapfrm=e?atol(e):0; }
      if(snapfrm){ armed=(long)g_frame>=snapfrm; }
      else if(nf>5000) armed=1;
      int snapcap=snapfrm?48:16;
      static int snapq=-1;
      if(snapq<0) snapq=getenv("PS3_RSX_SNAPQUAD")?1:0;
      static uint32_t snaptex=0xffffffffu;
      if(snaptex==0xffffffffu){ const char* e=getenv("PS3_RSX_SNAPTEX");
                                snaptex=e?(uint32_t)strtoul(e,0,16):0; }
      static uint32_t snaparm=0xffffffffu;
      if(snaparm==0xffffffffu){ const char* e=getenv("PS3_RSX_SNAPARM");
                                snaparm=e?(uint32_t)strtoul(e,0,16):0; }
      static int armed2=0;
      if(snaparm){
          uint32_t fh=(uint32_t)fnv1a(g_fp_words,g_fp_nwords*4,0xcbf29ce484222325ull);
          if(fh==snaparm&&rt->ea==snapea) armed2=1;
          if(!armed2) armed=0;
      }
      uint32_t u0ea=0;
      if(snaptex&&(texu&1)){
          uint32_t l0=(g_rsx.tex[0].format&3)?((g_rsx.tex[0].format&3)-1):0;
          u0ea=resolve(g_rsx.tex[0].offset,l0);
      }
      int want_snap = (snapn>0&&(int)nf>=snapn&&sk<4) ||
                      (snapea&&armed&&rt->ea==snapea&&sk<snapcap&&
                       (!snapq||(nf<=8&&prim==8))&&
                       (!snaptex||u0ea==snaptex));
      if(want_snap){
          rp_end(); cmd_begin();
          VkImageMemoryBarrier b4={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
              .srcAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
              .dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,
              .oldLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
              .newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
              .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
              .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
              .image=rt->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
          vkCmdPipelineBarrier(g_cmd,stages_for(b4.srcAccessMask,1),
            stages_for(b4.dstAccessMask,0),0,0,0,0,0,1,&b4);
          VkBufferImageCopy bic2={.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
              .imageExtent={rt->w,rt->h,1}};
          tstage_settle();
          vkCmdCopyImageToBuffer(g_cmd,rt->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
              g_tbuf,1,&bic2);
          b4.srcAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
          b4.dstAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
          b4.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
          b4.newLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
          vkCmdPipelineBarrier(g_cmd,stages_for(b4.srcAccessMask,1),
            stages_for(b4.dstAccessMask,0),0,0,0,0,0,1,&b4);
          cmd_submit();
          char pth[64]; snprintf(pth,sizeof pth,"out/snap_%d.bmp",sk++);
          write_bmp(pth,g_tptr,rt->w,rt->h);
          { char fp2[64]; snprintf(fp2,sizeof fp2,"out/snapfp_%d.bin",sk-1);
            FILE* g=fopen(fp2,"wb");
            if(g){ fwrite(g_fp_words,4,g_fp_nwords,g); fclose(g); }
            snprintf(fp2,sizeof fp2,"out/snapvp_%d.bin",sk-1);
            g=fopen(fp2,"wb");
            if(g){ uint32_t st2=g_rsx.vp_start&0x1ff;
                for(uint32_t i3=st2;i3<512;i3++){
                    fwrite(g_rsx.vp_instr[i3],1,16,g);
                    if(g_rsx.vp_instr[i3][3]&1) break; }
                fclose(g); }
            snprintf(fp2,sizeof fp2,"out/snapvc_%d.bin",sk-1);
            g=fopen(fp2,"wb");
            if(g){ fwrite(g_rsx.vp_const,16,468,g); fclose(g); } }
          for(uint32_t u2=0;u2<16;u2++) if(texu&(1u<<u2)){
              RsxTexture* t2=&g_rsx.tex[u2];
              uint32_t l2=(t2->format&3)?((t2->format&3)-1):0;
              fprintf(stderr,"[RSXD]   snap%d u%u kind=%c ea=0x%x fmt=0x%x rect=%ux%u remap=0x%x\n",
                      sk-1,u2,tkind[u2]?tkind[u2]:'?',resolve(t2->offset,l2),
                      (t2->format>>8)&0xff,(t2->image_rect>>16)&0xffff,
                      t2->image_rect&0xffff,t2->control1); }
          fprintf(stderr,"[RSXD] snap %d fp=%08x nf=%u tex=0x%x prim=%u rt=0x%x(%ux%u) "
                  "blend=%u(%x/%x eq=%x) cmask=0x%x depth=%u/%x\n",
                  sk-1,(uint32_t)fnv1a(g_fp_words,g_fp_nwords*4,0xcbf29ce484222325ull),
                  nf,texu,prim,rt->ea,rt->w,rt->h,
                  g_rsx.blend_enable,g_rsx.blend_sfactor,
                  g_rsx.blend_dfactor,g_rsx.blend_eq,g_rsx.color_mask,
                  g_rsx.depth_test,g_rsx.depth_func);
          if(nf<=8&&(used&1)){
              for(uint32_t vi=0;vi<nuniq&&vi<4;vi++){ float vq[4];
                  staged_vertex(0,vord[vi],vq);
                  fprintf(stderr,"[RSXD]   v%u=(%.3f,%.3f,%.3f,%.3f)\n",
                          vi,vq[0],vq[1],vq[2],vq[3]); }
          }
      } }
    { static int cdump=-1; static uint32_t cwant; static int cn;
      if(cdump<0){ const char* e=getenv("PS3_RSX_CDUMP");
                   cdump=e?1:0; cwant=(e&&e[0]!='1')?(uint32_t)strtoul(e,0,16):0; }
      if(cdump&&cn<4&&(cwant||(texu&(1u<<13)))){
          uint32_t fh=(uint32_t)fnv1a(g_fp_words,g_fp_nwords*4,0xcbf29ce484222325ull);
          if(cwant&&fh!=cwant) goto cdump_done;
          char pth[64]; FILE* g;
          snprintf(pth,sizeof pth,"out/cdump%d_const.bin",cn);
          g=fopen(pth,"wb"); if(g){ fwrite(g_rsx.vp_const,16,468,g); fclose(g); }
          snprintf(pth,sizeof pth,"out/cdump%d_vp.bin",cn);
          g=fopen(pth,"wb");
          if(g){ uint32_t st2=g_rsx.vp_start&0x1ff;
              for(uint32_t i3=st2;i3<512;i3++){
                  fwrite(g_rsx.vp_instr[i3],1,16,g);
                  if(g_rsx.vp_instr[i3][3]&1) break; }
              fclose(g); }
          snprintf(pth,sizeof pth,"out/cdump%d_fp.bin",cn);
          g=fopen(pth,"wb"); if(g){ fwrite(g_fp_words,4,g_fp_nwords,g); fclose(g); }
          fprintf(stderr,"[CDUMP] %d fp=%08x rt=0x%x(%ux%u) nf=%u nv=%u attrs=0x%x "
                  "tex=0x%x vpstart=%u\n",cn,fh,rt->ea,rt->w,rt->h,nf,nv,used,texu,
                  g_rsx.vp_start);
          for(uint32_t a2=0;a2<16;a2++) if(used&(1u<<a2)){
              float vq[4]; staged_vertex(a2,vord[0],vq);
              fprintf(stderr,"[CDUMP]   a%u v0=(%.4f,%.4f,%.4f,%.4f)\n",
                      a2,vq[0],vq[1],vq[2],vq[3]);
              float lo[4]={1e30f,1e30f,1e30f,1e30f}, hi[4]={-1e30f,-1e30f,-1e30f,-1e30f};
              for(uint32_t vi=0;vi<nuniq;vi++){ float vv[4];
                  staged_vertex(a2,vord[vi],vv);
                  for(int k=0;k<4;k++){
                      if(vv[k]<lo[k]) lo[k]=vv[k];
                      if(vv[k]>hi[k]) hi[k]=vv[k]; } }
              fprintf(stderr,"[CDUMP]   a%u bbox min=(%.4f,%.4f,%.4f,%.4f) "
                      "max=(%.4f,%.4f,%.4f,%.4f) over %u verts\n",
                      a2,lo[0],lo[1],lo[2],lo[3],hi[0],hi[1],hi[2],hi[3],nuniq); }
          static const int ci[]={84,130,142,143,144,145,146,160,161,162,163,
                                 165,166,167,168,169,170,171,190,197,198,199,
                                 200,201,202,203,204,216,464,465,466,467};
          for(unsigned k=0;k<sizeof ci/sizeof*ci;k++)
              fprintf(stderr,"[CDUMP]   c[%d] = %g %g %g %g   (age %u draws)\n",
                      ci[k],
                      g_rsx.vp_const[ci[k]][0],g_rsx.vp_const[ci[k]][1],
                      g_rsx.vp_const[ci[k]][2],g_rsx.vp_const[ci[k]][3],
                      g_rsx.draw_serial-g_rsx.vp_const_stamp[ci[k]]);
          cn++;
      }
      cdump_done: ; }
    { static uint32_t want=0xffffffffu;
      if(want==0xffffffffu){ const char* e=getenv("PS3_RSX_DUMPFP");
                             want=e?(uint32_t)strtoul(e,0,16):0; }
      { static int bigdbg=-1; if(bigdbg<0) bigdbg=rsxd_diag_on("PS3_RSX_BIGDRAW","PS3_RSX_NOBIGDRAW");
        int bignew=0;
        if(bigdbg&&nf>=600){
            static uint32_t bsig[192]; static int nbsig;
            static uint64_t bera=~0ull;
            if(bera!=g_frame/512){ bera=g_frame/512; nbsig=0; }
            uint32_t sig=rt->ea^(prim*2654435761u)^(used*40503u);
            for(int a2=0;a2<16;a2++) sig^=g_rsx.vtx[a2].format*(uint32_t)(a2*2246822519u+1u);
            bignew=1;
            for(int i2=0;i2<nbsig;i2++) if(bsig[i2]==sig){ bignew=0; break; }
            if(bignew&&nbsig<192) bsig[nbsig++]=sig; else bignew=0;
        }
        if(bignew){ {
            fprintf(stderr,"[BIGDRAW] rt=0x%x(%ux%u) nf=%u nv=%u prim=%u attrs=0x%x tex=0x%x\n",
                    rt->ea,rt->w,rt->h,nf,nv,prim,used,texu);
            for(uint32_t a2=0;a2<16;a2++) if(used&(1u<<a2)){
                uint32_t f2=g_rsx.vtx[a2].format;
                float vpa[4],vpb[4];
                staged_vertex(a2,vord[0],vpa);
                staged_vertex(a2,nuniq>1?vord[1]:vord[0],vpb);
                uint32_t o2=g_rsx.vtx[a2].offset, l2=(o2>>31)&1;
                uint32_t e2=resolve((o2&0x7fffffff)+g_rsx.vtx_base_off,l2);
                fprintf(stderr,"   a%u fmt=0x%08x type=%u size=%u stride=%u freq=%u "
                        "off=0x%x ea=0x%x v0=(%.3f,%.3f,%.3f,%.3f) v1=(%.3f,%.3f,%.3f,%.3f)\n",
                        a2,f2,f2&0xf,(f2>>4)&0xf,(f2>>8)&0xff,(f2>>16)&0xffff,o2,
                        e2?e2+vmin*((f2>>8)&0xff):0,
                        vpa[0],vpa[1],vpa[2],vpa[3],vpb[0],vpb[1],vpb[2],vpb[3]);
                if(e2){ const uint8_t* rp=g_base+e2+(size_t)vmin*((f2>>8)&0xff);
                    fprintf(stderr,"      raw:");
                    for(int k2=0;k2<32;k2++) fprintf(stderr,"%s%02x",(k2&3)?"":" ",rp[k2]);
                    fprintf(stderr,"\n"); }
            }
            fprintf(stderr,"   freq_div_op=0x%x base_off=0x%x base_idx=%u "
                    "c0=(%.3f,%.3f,%.3f,%.3f) "
                    "c1=(%.3f,%.3f,%.3f,%.3f) c2=(%.3f,%.3f,%.3f,%.3f) c3=(%.3f,%.3f,%.3f,%.3f)\n",
                    g_rsx.freq_div_op,g_rsx.vtx_base_off,g_rsx.vtx_base_idx,
                    g_rsx.vp_const[0][0],g_rsx.vp_const[0][1],g_rsx.vp_const[0][2],g_rsx.vp_const[0][3],
                    g_rsx.vp_const[1][0],g_rsx.vp_const[1][1],g_rsx.vp_const[1][2],g_rsx.vp_const[1][3],
                    g_rsx.vp_const[2][0],g_rsx.vp_const[2][1],g_rsx.vp_const[2][2],g_rsx.vp_const[2][3],
                    g_rsx.vp_const[3][0],g_rsx.vp_const[3][1],g_rsx.vp_const[3][2],g_rsx.vp_const[3][3]);
        } } }
      if(want&&rt->ea==want){ static int dk;
          if(dk<8){ char pth[64]; snprintf(pth,sizeof pth,"out/fpdraw_%d.bin",dk);
              FILE* f=fopen(pth,"wb");
              if(f){ fwrite(g_fp_words,4,g_fp_nwords,f); fclose(f); }
              fprintf(stderr,"[RSXD] dumped fpdraw_%d (rt=0x%x tex=0x%x nf=%u)\n",
                      dk,rt->ea,texu,nf);
              dk++; } } }
    { static int dbg=-1;
      if(dbg<0) dbg=getenv("PS3_RSXDBG")?1:0;
      if(dbg){ static long dn; if(dn++<400)
          fprintf(stderr,"[RSXDBG] draw#%ld rt=0x%x(%ux%u) prim=%u nf=%u nv=%u "
                  "attrs=0x%x tex=0x%x vp=(%.0f,%.0f %.0fx%.0f)\n",
                  dn,rt->ea,rt->w,rt->h,prim,nf,nv,used,texu,
                  g_rsx.vp_offset[0]-g_rsx.vp_scale[0],
                  g_rsx.vp_offset[1]-g_rsx.vp_scale[1],
                  g_rsx.vp_scale[0]*2,g_rsx.vp_scale[1]*2);
      if(dn<=400&&(used&1)){
          float v0[4]; staged_vertex(0,vord[0],v0);
          fprintf(stderr,"[RSXDBG]   v0=(%.2f,%.2f,%.2f,%.2f) c0=(%.2f,%.2f,%.2f,%.2f) "
                  "c1=(%.2f,%.2f,%.2f,%.2f)\n",
                  v0[0],v0[1],v0[2],v0[3],
                  g_rsx.vp_const[0][0],g_rsx.vp_const[0][1],g_rsx.vp_const[0][2],g_rsx.vp_const[0][3],
                  g_rsx.vp_const[1][0],g_rsx.vp_const[1][1],g_rsx.vp_const[1][2],g_rsx.vp_const[1][3]);
          fprintf(stderr,"[RSXDBG]   c467=(%.2f,%.2f,%.2f,%.2f) vpstart=%u cmask=0x%x fpctrl=0x%x sciss=0x%x/0x%x\n",
                  g_rsx.vp_const[467][0],g_rsx.vp_const[467][1],
                  g_rsx.vp_const[467][2],g_rsx.vp_const[467][3],g_rsx.vp_start,
                  g_rsx.color_mask,g_rsx.fp_control,g_rsx.scissor_h,g_rsx.scissor_v); } }
    }
    g_narr=0; g_nidx=0;
}

static void rsxd_clear_inner(uint32_t mask);
void rsxd_clear(uint32_t mask){
    DP_T0(t); rsxd_clear_inner(mask); DP_T1(DP_CLEAR,t);
}
static void rsxd_clear_inner(uint32_t mask){
    if(!draw_up()) return;
    Surf* rt=current_rt();
    if(!rt) return;
    rp_begin(rt);
    VkClearAttachment ca[2]; uint32_t nca=0;
    VkClearRect cr={.rect=scissor_rect(rt),.layerCount=1};
    if(!cr.rect.extent.width||!cr.rect.extent.height) return;
    static int dbgclr2=-1;
    if(dbgclr2<0) dbgclr2=getenv("PS3_RSXDBGCLR")?1:0;
    if(dbgclr2) g_rsx.clear_color=0xffff00ff;
    if(mask&0xf0){
        uint32_t c=g_rsx.clear_color;
        ca[nca].aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
        ca[nca].colorAttachment=0;
        ca[nca].clearValue.color.float32[0]=(float)((c>>16)&0xff)/255.0f;
        ca[nca].clearValue.color.float32[1]=(float)((c>>8)&0xff)/255.0f;
        ca[nca].clearValue.color.float32[2]=(float)(c&0xff)/255.0f;
        ca[nca].clearValue.color.float32[3]=(float)((c>>24)&0xff)/255.0f;
        nca++;
    }
    if(mask&GCM_CLEAR_Z){
        static struct { uint32_t ea,w,h,zea,zv; } seen[24]; static int nseen;
        int isnew=1;
        for(int i=0;i<nseen;i++)
            if(seen[i].ea==rt->ea&&seen[i].w==rt->w&&seen[i].h==rt->h&&
               seen[i].zea==rt->zea&&seen[i].zv==g_rsx.clear_zstencil){ isnew=0; break; }
        if(qprobe_on())
            fprintf(stderr,"[QPROBE] #%u CLEAR z rt=0x%x %ux%u zea=0x%x -> %.6f\n",
                    g_rsx.draw_serial,rt->ea,rt->w,rt->h,rt->zea,
                    (float)(g_rsx.clear_zstencil>>8)/16777215.0f);
        if(isnew&&nseen<24){
            seen[nseen].ea=rt->ea; seen[nseen].w=rt->w; seen[nseen].h=rt->h;
            seen[nseen].zea=rt->zea; seen[nseen].zv=g_rsx.clear_zstencil; nseen++;
            uint32_t zf=(g_rsx.surface_format>>5)&7;
            fprintf(stderr,"[RSXD] Zclear mask=0x%x -> rt=0x%x %ux%u zea=0x%x  "
                    "zstencil=0x%08x -> depth=%.6f  cmask=0x%x ctarget=%u "
                    "ztest=%u zmask=%u zfmt=%u\n",
                    mask,rt->ea,rt->w,rt->h,rt->zea,g_rsx.clear_zstencil,
                    (zf==1)?(float)(g_rsx.clear_zstencil&0xffff)/65535.0f
                           :(float)(g_rsx.clear_zstencil>>8)/16777215.0f,
                    g_rsx.color_mask,g_rsx.color_target,g_rsx.depth_test,
                    g_rsx.depth_mask,zf);
        }
    }
    if(mask&GCM_CLEAR_Z){
        uint32_t zfmt=(g_rsx.surface_format>>5)&7;
        uint32_t zv=g_rsx.clear_zstencil;
        ca[nca].aspectMask=VK_IMAGE_ASPECT_DEPTH_BIT;
        ca[nca].colorAttachment=0;
        ca[nca].clearValue.depthStencil.depth=(zfmt==1)
            ? (float)(zv&0xffff)/65535.0f : (float)(zv>>8)/16777215.0f;
        ca[nca].clearValue.depthStencil.stencil=0;
        nca++;
    }
    if(nca) vkCmdClearAttachments(g_cmd,nca,ca,1,&cr);
}

void rsxd_i2d_word(uint32_t arg){
    g_fp_epoch++;
    uint32_t idx=g_rsx.i2d.idx++;
    uint32_t dloc=dma_loc(g_rsx.s2d.dst_dma);
    uint32_t dea=resolve(g_rsx.s2d.off_dst,dloc);
    if(!dea) return;
    uint32_t fmt=g_rsx.i2d.format&0xffff;
    uint32_t bpp=(fmt==4)?2:4;
    uint32_t pitch=(g_rsx.s2d.pitch>>16)&0xffff;
    if(!pitch) pitch=0x1000;
    uint32_t x=g_rsx.i2d.point&0xffff, y=g_rsx.i2d.point>>16;
    uint32_t w=g_rsx.i2d.size_in&0xffff;
    if(!w) return;
    uint32_t px_per_word=4/bpp;
    uint32_t px=idx*px_per_word;
    uint32_t row=y+px/w, col=x+px%w;
    uint32_t oh=g_rsx.i2d.size_out>>16;
    if(oh&&row>=y+oh) return;
    uint64_t doff=(uint64_t)dea+(uint64_t)row*pitch+(uint64_t)col*bpp;
    if(doff+4>g_mem_size) return;
    uint8_t* d=g_base+doff;
    if(bpp==4){
        d[0]=(uint8_t)(arg>>24); d[1]=(uint8_t)(arg>>16);
        d[2]=(uint8_t)(arg>>8);  d[3]=(uint8_t)arg;
    } else {
        d[0]=(uint8_t)(arg>>24); d[1]=(uint8_t)(arg>>16);
        if(px%w+1<w){ d[2]=(uint8_t)(arg>>8); d[3]=(uint8_t)arg; }
    }
    { static long in3; if(++in3<=8)
        fprintf(stderr,"[RSXD] i2d word#%u fmt=0x%x -> ea=0x%x (+%u,%u) pitch=%u\n",
                idx,fmt,dea,col,row,pitch); }
}

void rsxd_report(uint32_t arg){
    uint32_t off=arg&0xffffff, type=arg>>24;
    uint32_t ea;
    if(g_rsx.ctx_dma_report==0x66626660u){
        if((uint64_t)0x0e000000u+off+16>(uint64_t)g_local_size) return;
        ea=g_local_ea+0x0e000000u+off;
    } else {
        ea=g_ioff2ea?g_ioff2ea(off):0;
        if(!ea) return;
        if((uint64_t)ea+16>g_mem_size) return;
    }
    static uint64_t ts;
    ts+=1000;
    uint32_t value=100;
    uint8_t* d=g_base+ea;
    for(int i=0;i<8;i++) d[i]=(uint8_t)(ts>>((7-i)*8));
    d[8]=(uint8_t)(value>>24); d[9]=(uint8_t)(value>>16);
    d[10]=(uint8_t)(value>>8); d[11]=(uint8_t)value;
    d[12]=d[13]=d[14]=d[15]=0;
    { static long rn; if(++rn<=8)
        fprintf(stderr,"[RSXD] report type=%u off=0x%x -> ea=0x%x\n",type,off,ea); }
}

static void wb_flush(void);
void rsxd_bench_reset(void){
    for(int i=0;i<DP_N;i++) g_dpacc[i]=0;
    g_dpdraws=g_dpverts=g_dptris=g_dptexdec=g_dppipenew=g_dppipeevict=0;
    g_dpsubmits=g_dpsubmit_ticks=0;
    g_dpflip_wb=g_dpflip_present=g_dpflip_retire=0;
    g_dpvpcskip=g_dpdsethit=g_dpfpmemo=g_dpi16=0;
    g_dpvbytes=g_dpvbytes16=0;
}
double rsxd_bench_line(char* out, size_t cap, int frames){
    if(out&&cap) out[0]=0;
    if(frames<=0) return 0.0;
    static uint64_t freq;
    if(!freq){ LARGE_INTEGER f; QueryPerformanceFrequency(&f); freq=(uint64_t)f.QuadPart; }
    double per=1000.0/(double)frames;
    double sum=0; int o=0;
    for(int i=0;i<DP_N;i++){
        double ms=(double)g_dpacc[i]/(double)freq*per;
        sum+=ms;
        if(out&&ms>=0.05&&o<(int)cap-24)
            o+=snprintf(out+o,cap-o," %s=%.2f",g_dpname[i],ms);
    }
    if(out&&o<(int)cap-160)
        snprintf(out+o,cap-o,
                 "  [flip: f32wb=%.2f present=%.2f retire=%.2f]"
                 "  draws=%.0f verts=%.0f tris=%.0f pipes=%d vtxMB=%.2f",
                 (double)g_dpflip_wb/(double)freq*per,
                 (double)g_dpflip_present/(double)freq*per,
                 (double)g_dpflip_retire/(double)freq*per,
                 (double)g_dpdraws/frames,(double)g_dpverts/frames,
                 (double)g_dptris/frames,g_npipe,
                 (double)g_dpvbytes/frames/1048576.0);
    return sum;
}

static void dprof_dump(void){
    if(!dprof_on()) return;
    { static int bench=-1; if(bench<0) bench=getenv("PS3_BENCH")?1:0;
      if(bench) return; }
    static uint64_t freq, w0; static int frames;
    if(!freq){ LARGE_INTEGER f; QueryPerformanceFrequency(&f); freq=(uint64_t)f.QuadPart; }
    frames++;
    uint64_t now=dp_now();
    if(!w0){ w0=now; return; }
    if(now-w0 < freq*5) return;
    double secs=(double)(now-w0)/(double)freq;
    double perf=frames?1000.0/(double)frames:0.0;
    char line[512]; int o=snprintf(line,sizeof line,"[DRAWPROF] %.1ffps",
                                   frames/secs);
    double sum=0;
    for(int i=0;i<DP_N;i++){
        double ms=(double)g_dpacc[i]/(double)freq*perf;
        sum+=ms;
        if(ms>=0.05) o+=snprintf(line+o,sizeof line-o," %s=%.1f",g_dpname[i],ms);
    }
    o+=snprintf(line+o,sizeof line-o,
                " | total=%.1fms/f draws=%.0f verts=%.0f tris=%.0f "
                "texdec=%.0f newpipe=%.0f pipes=%d fpstruct=%d submit=%.1fx%.1fms",
                sum,(double)g_dpdraws/frames,(double)g_dpverts/frames,
                (double)g_dptris/frames,(double)g_dptexdec/frames,
                (double)g_dppipenew/frames,g_npipe,g_dpfpstruct,
                (double)g_dpsubmits/frames,
                g_dpsubmits?(double)g_dpsubmit_ticks/(double)freq*1000.0/(double)g_dpsubmits:0.0);
    if(g_dppipeevict) o+=snprintf(line+o,sizeof line-o," evict=%.1f",
                                  (double)g_dppipeevict/frames);
    o+=snprintf(line+o,sizeof line-o," [flip: f32wb=%.1f present=%.1f retire=%.1f]",
                (double)g_dpflip_wb/(double)freq*perf,
                (double)g_dpflip_present/(double)freq*perf,
                (double)g_dpflip_retire/(double)freq*perf);
    g_dpflip_wb=g_dpflip_present=g_dpflip_retire=0;
    o+=snprintf(line+o,sizeof line-o," ringMB v=%.1f/%u i=%.1f/%u u=%.1f/%u t=%.1f/%u",
                g_dpvhi/1048576.0,(unsigned)(VBUF_CAP>>20),
                g_dpihi/1048576.0,(unsigned)(IBUF_CAP>>20),
                g_dpuhi/1048576.0,(unsigned)(UBUF_CAP>>20),
                g_dpthi/1048576.0,(unsigned)(TBUF_CAP>>20));
    g_dpvhi=g_dpihi=g_dpuhi=g_dpthi=0;
    fprintf(stderr,"%s\n",line);
    for(int i=0;i<DP_N;i++) g_dpacc[i]=0;
    g_dpdraws=g_dpverts=g_dptris=g_dptexdec=g_dppipenew=g_dppipeevict=0;
    g_dpsubmits=g_dpsubmit_ticks=0;
    w0=now; frames=0;
}
static void cachestats_dump(void){
    static int on=-1;
    if(on<0) on=getenv("PS3_RSX_CACHESTATS")?1:0;
    if(!on) return;
    static uint64_t l_d,l_v,l_s,l_m,l_i,l_b,l_b16;
    if(g_dpdraws<l_d){ l_d=l_v=l_s=l_m=l_i=l_b=l_b16=0; }
    uint64_t d=g_dpdraws-l_d, v=g_dpvpcskip-l_v, s=g_dpdsethit-l_s,
             m=g_dpfpmemo-l_m, i2=g_dpi16-l_i,
             vb=g_dpvbytes-l_b, vb16=g_dpvbytes16-l_b16;
    l_d=g_dpdraws; l_v=g_dpvpcskip; l_s=g_dpdsethit; l_m=g_dpfpmemo; l_i=g_dpi16;
    l_b=g_dpvbytes; l_b16=g_dpvbytes16;
    if(!d) return;
    fprintf(stderr,"[CACHE] frame %llu draws=%llu | vpc-skip=%llu (%.0f%%) "
            "dset-reuse=%llu (%.0f%%) fp-memo=%llu (%.0f%%) idx16=%llu (%.0f%%) "
            "| vtxMB=%.2f was %.2f (%.0f%%)\n",
            (unsigned long long)g_frame,(unsigned long long)d,
            (unsigned long long)v,100.0*(double)v/(double)d,
            (unsigned long long)s,100.0*(double)s/(double)d,
            (unsigned long long)m,100.0*(double)m/(double)d,
            (unsigned long long)i2,100.0*(double)i2/(double)d,
            vb/1048576.0,vb16/1048576.0,
            vb16?100.0*(double)vb/(double)vb16:0.0);
}

static void snap_surface_bmp(Surf* sf, const char* path){
    VkDeviceSize need=(VkDeviceSize)sf->w*sf->h*4;
    if(!sf->img||!sf->inited||need>TBUF_CAP) return;
    cmd_begin();
    VkImageLayout from = sf->layout==1?VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                       : sf->layout==2?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
                       : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_MEMORY_WRITE_BIT,
        .dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,
        .oldLayout=from,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=sf->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    VkBufferImageCopy bic={.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
        .imageExtent={sf->w,sf->h,1}};
    tstage_settle();
    vkCmdCopyImageToBuffer(g_cmd,sf->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        g_tbuf,1,&bic);
    sf->layout=2;
    cmd_submit();
    write_bmp(path,g_tptr,sf->w,sf->h);
}

static void rsxd_statecap(const char* dir){
    char p[320];
    snprintf(p,sizeof p,"%s/rsx.txt",dir);
    FILE* f=fopen(p,"wb");
    if(f){
        fprintf(f,"frame=%llu pipelines=%d textures/samplers=%d/%d\n\n",
                (unsigned long long)g_frame,g_npipe,NTEX,g_nsamp);
        fprintf(f,"== surfaces ==\n");
        for(int i=0;i<NSURF;i++){
            Surf* s=&g_surf[i];
            if(!s->img) continue;
            fprintf(f,"  ea=0x%08x %4ux%-4u %s inited=%d layout=%d "
                      "zea=0x%08x zpitch=%u zfloat=%d last_frame=%llu\n",
                    s->ea,s->w,s->h,s->isf?"F32":"U8 ",s->inited,s->layout,
                    s->zea,s->zpitch,s->zfloat,(unsigned long long)s->last_frame);
        }
        fprintf(f,"\n== texture cache ==\n");
        for(int i=0;i<NTEX;i++){
            Tex* t=&g_tex[i];
            if(!t->img) continue;
            fprintf(f,"  ea=0x%08x fmt=0x%02x rect=%ux%u mips=%u type=%u depth=%u "
                      "ready=%d last=%llu used=%llu\n",
                    t->ea,t->fmt&0xff,(t->rect>>16)&0xffff,t->rect&0xffff,
                    t->nmip,t->type,t->depth,t->ready,
                    (unsigned long long)t->last_frame,
                    (unsigned long long)t->use_frame);
        }
        fprintf(f,"\n== RSX register state (the words a draw would use now) ==\n");
        fprintf(f,"  surface: colorA off=0x%08x pitch=%u loc=%u | zeta off=0x%08x "
                  "pitch=%u loc=%u | format=0x%08x target=%u clip=%08x/%08x\n",
                g_rsx.color[0].offset,g_rsx.color[0].pitch,g_rsx.color[0].location,
                g_rsx.zeta.offset,g_rsx.zeta.pitch,g_rsx.zeta.location,
                g_rsx.surface_format,g_rsx.color_target,g_rsx.clip_h,g_rsx.clip_v);
        fprintf(f,"  viewport h=0x%08x v=0x%08x scale=%g,%g,%g,%g offset=%g,%g,%g,%g\n",
                g_rsx.viewport_h,g_rsx.viewport_v,
                g_rsx.vp_scale[0],g_rsx.vp_scale[1],g_rsx.vp_scale[2],g_rsx.vp_scale[3],
                g_rsx.vp_offset[0],g_rsx.vp_offset[1],g_rsx.vp_offset[2],g_rsx.vp_offset[3]);
        fprintf(f,"  scissor h=0x%08x v=0x%08x\n",g_rsx.scissor_h,g_rsx.scissor_v);
        fprintf(f,"  depth: test=%u func=0x%x mask=%u control0=0x%08x\n",
                g_rsx.depth_test,g_rsx.depth_func,g_rsx.depth_mask,g_rsx.control0);
        fprintf(f,"  blend: en=%u sf=0x%x df=0x%x eq=0x%x colormask=0x%x\n",
                g_rsx.blend_enable,g_rsx.blend_sfactor,g_rsx.blend_dfactor,
                g_rsx.blend_eq,g_rsx.color_mask);
        fprintf(f,"  alpha test: en=%u func=0x%x ref=0x%x\n",
                g_rsx.alpha_test,g_rsx.alpha_func,g_rsx.alpha_ref);
        fprintf(f,"  cull: en=%u face=0x%x front=0x%x  prim in flight=%u\n",
                g_rsx.cull_enable,g_rsx.cull_face,g_rsx.front_face,g_rsx.prim);
        fprintf(f,"  point: size=0x%08x sprite=0x%08x params_en=%u\n",
                g_rsx.point_size_u32,g_rsx.point_sprite,g_rsx.point_params_en);
        fprintf(f,"  programs: fp_offset=0x%08x fp_control=0x%08x vp_start=%u "
                  "vp_in=0x%08x vp_out=0x%08x\n",
                g_rsx.fp_offset_raw,g_rsx.fp_control,g_rsx.vp_start,
                g_rsx.vp_in_mask,g_rsx.vp_out_mask);
        fprintf(f,"\n== vertex arrays ==\n");
        for(int a=0;a<16;a++){
            uint32_t fmt=g_rsx.vtx[a].format;
            if(!(fmt&0xf)||!((fmt>>4)&0xf)) continue;
            fprintf(f,"  a%-2d format=0x%08x offset=0x%08x\n",a,fmt,g_rsx.vtx[a].offset);
        }
        fclose(f);
    }
    for(int i=0;i<NSURF;i++){
        Surf* s=&g_surf[i];
        if(!s->img||!s->inited) continue;
        snprintf(p,sizeof p,"%s/rt_%08x_%ux%u.bmp",dir,s->ea,s->w,s->h);
        snap_surface_bmp(s,p);
    }
    snprintf(p,sizeof p,"%s/capture.rsxc",dir);
    cap_request(p,1);
}

static int rsxd_flip_present_inner(uint32_t disp_ea, uint32_t w, uint32_t h);
int rsxd_flip_present(uint32_t disp_ea, uint32_t w, uint32_t h){
    DP_T0(t);
    int r=rsxd_flip_present_inner(disp_ea,w,h);
    if(g_nretired){
        cmd_submit();
        cmd_retire(g_cmdi);
        for(int i=0;i<g_nretired;i++) vkDestroyPipeline(g_dev,g_pipe_retired[i],NULL);
        g_nretired=0;
    }
    DP_T1(DP_FLIP,t);
    cachestats_dump();
    dprof_dump();
    return r;
}
static int rsxd_flip_present_inner(uint32_t disp_ea, uint32_t w, uint32_t h){
    { static int wb=-1; if(wb<0) wb=getenv("PS3_RSX_WB")?1:0;
      if(g_up>0&&wb) wb_flush(); else g_nwb=0; }
    DP_T0(t_wb);
    { static int df=-1; if(df<0) df=getenv("PS3_RSX_DUMPF32")?1:0;
      static int nof=-1; if(nof<0) nof=getenv("PS3_RSX_NOF32WB")?1:0;
      static int syncwb=-1; if(syncwb<0) syncwb=getenv("PS3_RSX_SYNCF32WB")?1:0;
      if(g_up>0&&!nof){
        if(!syncwb) wb_drain((g_wbslot + WB_SLOTS - 1) % WB_SLOTS, df);

        int slot=g_wbslot; int n2=0;
        uint32_t off=0;
        rp_end(); cmd_begin();
        for(int i=0;i<NSURF;i++){ Surf* sf=&g_surf[i];
            if(!sf->img||!sf->inited) continue;
            static int allwb=-1; if(allwb<0) allwb=getenv("PS3_RSX_ALLWB")?1:0;
            if(sf->isf){ if(sf->w>64) continue; }
            else       { if(!allwb||sf->w>128||sf->h>128) continue; }
            uint32_t need=sf->w*sf->h*(sf->isf?16u:4u);
            if(n2>=WB_MAX || off+need>WBUF_CAP) break;
            surf_to_layout(sf,2);
            VkBufferImageCopy bc={.bufferOffset=off,
                .imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
                .imageExtent={sf->w,sf->h,1}};
            vkCmdCopyImageToBuffer(g_cmd,sf->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                g_wbuf[slot],1,&bc);
            g_wbent[slot][n2]=(WbEnt){sf->ea,sf->w,sf->h,off,sf->isf};
            n2++; off+=(need+15u)&~15u;
        }
        g_wbn[slot]=n2;
        if(n2){
            g_wbcmd[slot]=g_cmdi;
            if(syncwb){ cmd_submit(); wb_drain(slot,df); }
            else        g_wbslot=(slot+1)%WB_SLOTS;
        } else g_wbcmd[slot]=-1;
      } }
    if(dprof_on()) g_dpflip_wb+=dp_now()-t_wb;
    tex_retire();
    g_frame++;
    g_fp_epoch++;
    { static int fmark=-1;
      if(fmark<0) fmark=(getenv("PS3_RSX_TEXDBG")||getenv("PS3_RSX_QPROBE")||
                         getenv("PS3_RSX_ZPROBE"))?1:0;
      if(fmark) fprintf(stderr,"[FRAME] %llu\n",(unsigned long long)g_frame); }
    if(dprof_on()){
        uint32_t vseg=VBUF_CAP/NFRAME, iseg=IBUF_CAP/NFRAME;
        uint32_t useg=UBUF_CAP/NFRAME;
        uint32_t v=g_voff-(g_vend-vseg), i2=g_ioff-(g_iend-iseg);
        uint32_t u=g_uoff-(g_uend-useg), t2=g_toff;
        if(v>g_dpvhi) g_dpvhi=v;   if(i2>g_dpihi) g_dpihi=i2;
        if(u>g_dpuhi) g_dpuhi=u;   if(t2>g_dpthi) g_dpthi=t2;
    }
    if(g_up<=0) return 0;
    cmd_flush();
    g_frame_last_cmd[g_fslot]=g_cmdi;
    g_frame_last_seq[g_fslot]=g_cmd_seq[g_cmdi];
    { int ws=(g_wbslot+WB_SLOTS-1)%WB_SLOTS;
      if(g_wbn[ws]&&g_wbcmd[ws]>=0) g_wbseq[ws]=g_cmd_seq[g_wbcmd[ws]]; }
    for(int i=0;i<g_nretired;i++){
        if(g_ndead[g_fslot]<(int)(sizeof g_pipe_dead[0]/sizeof g_pipe_dead[0][0]))
            g_pipe_dead[g_fslot][g_ndead[g_fslot]++]=g_pipe_retired[i];
        else { cmd_retire(g_cmdi); vkDestroyPipeline(g_dev,g_pipe_retired[i],NULL); }
    }
    g_nretired=0;
    g_fslot=(g_fslot+1)%NFRAME;
    { DP_T0(t_rt);
      cmd_retire_seq(g_frame_last_cmd[g_fslot],g_frame_last_seq[g_fslot]);
      if(dprof_on()) g_dpflip_retire+=dp_now()-t_rt; }
    for(int i=0;i<g_ndead[g_fslot];i++) vkDestroyPipeline(g_dev,g_pipe_dead[g_fslot][i],NULL);
    g_ndead[g_fslot]=0;
    vkResetDescriptorPool(g_dev,g_dpools[g_fslot],0);
    g_dpool=g_dpools[g_fslot];
    { uint32_t vseg=VBUF_CAP/NFRAME, iseg=IBUF_CAP/NFRAME, useg=UBUF_CAP/NFRAME;
      g_voff=(uint32_t)g_fslot*vseg; g_vend=g_voff+vseg;
      g_ioff=(uint32_t)g_fslot*iseg; g_iend=g_ioff+iseg;
      g_uoff=(uint32_t)g_fslot*useg; g_uend=g_uoff+useg; }
    g_vpc_valid=0; dset_cache_drop();
    if(g_tstaged){ g_tstage_slot=g_cmdi; g_tstage_seq=g_cmd_seq[g_cmdi]; g_tstaged=0; }
    g_toff=0; g_tend=TBUF_CAP;
    Surf* s=0;
    for(int sl=g_surfhead[surf_hkey(disp_ea)]; sl; sl=g_surf[sl-1].hnext){
        Surf* c2=&g_surf[sl-1];
        if(!c2->img||!c2->inited||c2->ea!=disp_ea) continue;
        if(w&&h&&c2->w==w&&c2->h==h){ s=c2; break; }
        if(!s||(uint64_t)c2->w*c2->h>(uint64_t)s->w*s->h||
           ((uint64_t)c2->w*c2->h==(uint64_t)s->w*s->h&&c2->last_frame>s->last_frame))
            s=c2;
    }
    if(!s){ cmd_submit(); return 0; }
    rp_end(); cmd_begin();
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT|VK_ACCESS_SHADER_READ_BIT,
        .dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,
        .oldLayout=surf_layout_enum(s),
        .newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=s->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    cmd_flush();
    { DP_T0(t_pr); rsxvk_present_image(s->img,s->w,s->h);
      if(dprof_on()) g_dpflip_present+=dp_now()-t_pr; }
    cmd_begin();
    b.srcAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
    b.dstAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    b.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    b.newLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    s->layout=0;
    cmd_flush();
    { static int shot2=-2, rtd=-2; static long fc2;
      if(shot2==-2){ const char* e=getenv("PS3_RSXSHOT"); shot2=e?atoi(e):0;
                     e=getenv("PS3_RSX_RTDUMP"); rtd=e?atoi(e):0; }
      ++fc2;
      if((shot2>0&&fc2==shot2)||(rtd>0&&(fc2%rtd)==0)){
          for(int i=0;i<NSURF;i++){
              Surf* sf=&g_surf[i];
              if(!sf->img||!sf->inited) continue;
              VkDeviceSize need=(VkDeviceSize)sf->w*sf->h*4;
              if(need>TBUF_CAP) continue;
              cmd_begin();
              VkImageLayout from = sf->layout==1?VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                                 : sf->layout==2?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
                                 : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
              VkImageMemoryBarrier b3={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                  .srcAccessMask=VK_ACCESS_MEMORY_WRITE_BIT,
                  .dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,
                  .oldLayout=from,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                  .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                  .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                  .image=sf->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
              vkCmdPipelineBarrier(g_cmd,stages_for(b3.srcAccessMask,1),
            stages_for(b3.dstAccessMask,0),0,0,0,0,0,1,&b3);
              VkBufferImageCopy bic={.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
                  .imageExtent={sf->w,sf->h,1}};
              tstage_settle();
              vkCmdCopyImageToBuffer(g_cmd,sf->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                  g_tbuf,1,&bic);
              sf->layout=2;
              cmd_submit();
              char pth[128]; snprintf(pth,sizeof pth,"out/rt_%08x_%ux%u.bmp",sf->ea,sf->w,sf->h);
              write_bmp(pth,g_tptr,sf->w,sf->h);
          }
      } }
    { static int zp=-2; static long fz;
      if(zp==-2){ const char* e=getenv("PS3_RSX_ZPROBE"); zp=e?atoi(e):0; }
      if(zp>0&&((++fz)%zp)==0){
          for(int i=0;i<NSURF;i++){
              Surf* sf=&g_surf[i];
              if(!sf->img||!sf->inited||!sf->z) continue;
              if(!sf->zea) continue;
              VkDeviceSize need=(VkDeviceSize)sf->w*sf->h*4;
              if(need>TBUF_CAP) continue;
              cmd_begin();
              VkImageMemoryBarrier zb2={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                  .srcAccessMask=VK_ACCESS_MEMORY_WRITE_BIT,
                  .dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,
                  .oldLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
                  .newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                  .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                  .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                  .image=sf->z,.subresourceRange={VK_IMAGE_ASPECT_DEPTH_BIT,0,1,0,1}};
              vkCmdPipelineBarrier(g_cmd,stages_for(zb2.srcAccessMask,1),
            stages_for(zb2.dstAccessMask,0),0,0,0,0,0,1,&zb2);
              VkBufferImageCopy zc2={.imageSubresource={VK_IMAGE_ASPECT_DEPTH_BIT,0,0,1},
                  .imageExtent={sf->w,sf->h,1}};
              tstage_settle();
              vkCmdCopyImageToBuffer(g_cmd,sf->z,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                  g_tbuf,1,&zc2);
              zb2.srcAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
              zb2.dstAccessMask=VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
              zb2.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
              zb2.newLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
              vkCmdPipelineBarrier(g_cmd,stages_for(zb2.srcAccessMask,1),
            stages_for(zb2.dstAccessMask,0),0,0,0,0,0,1,&zb2);
              cmd_submit();
              const float* zd=(const float*)g_tptr;
              float mn=1e30f,mx=-1e30f; double sum=0; long n=0,at0=0,at1=0;
              for(uint32_t y=0;y<sf->h;y+=2) for(uint32_t x=0;x<sf->w;x+=2){
                  float v=zd[(size_t)y*sf->w+x];
                  if(v<mn)mn=v; if(v>mx)mx=v; sum+=v; n++;
                  if(v<=0.0f) at0++; if(v>=1.0f) at1++; }
              if(n) fprintf(stderr,"[ZPROBE] ea=0x%x zea=0x%x %ux%u  min=%.9f "
                      "max=%.9f avg=%.9f  at0=%.1f%% at1=%.1f%%%s\n",
                      sf->ea,sf->zea,sf->w,sf->h,mn,mx,(float)(sum/n),
                      100.0*at0/n,100.0*at1/n,
                      (mn>=1.0f)?"   <-- NOTHING EVER WRITTEN (all far)":"");
          }
      } }
    { static int shot=-2; static long fc;
      if(shot==-2){ const char* e=getenv("PS3_RSXSHOT"); shot=e?atoi(e):0; }
      int req=g_shot_req; g_shot_req=0; ++fc;
      if(req||(shot>0&&(fc%shot)==0)){
          VkDeviceSize need=(VkDeviceSize)s->w*s->h*4;
          if(need<=TBUF_CAP){
              cmd_begin();
              VkImageMemoryBarrier b2={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                  .srcAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
                  .dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,
                  .oldLayout=surf_layout_enum(s),
                  .newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                  .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                  .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
                  .image=s->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
              vkCmdPipelineBarrier(g_cmd,stages_for(b2.srcAccessMask,1),
            stages_for(b2.dstAccessMask,0),0,0,0,0,0,1,&b2);
              VkBufferImageCopy bic={.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
                  .imageExtent={s->w,s->h,1}};
              tstage_settle();
              vkCmdCopyImageToBuffer(g_cmd,s->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                  g_tbuf,1,&bic);
              b2.srcAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
              b2.dstAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
              b2.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
              b2.newLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
              vkCmdPipelineBarrier(g_cmd,stages_for(b2.srcAccessMask,1),
            stages_for(b2.dstAccessMask,0),0,0,0,0,0,1,&b2);
              s->layout=0;
              cmd_submit();
              write_bmp("out/rsxshot.bmp",g_tptr,s->w,s->h);
          }
      } }
    if(g_ptbuf&&g_ptptr){
        FILE* f=fopen("out/pixtrace.bin","wb");
        if(f){ fwrite(g_ptptr,1,PTBUF_CAP,f); fclose(f); }
        const float* p=(const float*)g_ptptr;
        fprintf(stderr,"[PIXTRACE] hits per quad pixel: %g %g %g %g "
                "(first frag at %.1f,%.1f) -> out/pixtrace.bin\n",
                p[0],p[544*4],p[2*544*4],p[3*544*4],p[1],p[2]);
    }
    if(statecap_rsx_pending()){
        rsxd_statecap(statecap_dir());
        statecap_rsx_done();
    }
    return 1;
}
