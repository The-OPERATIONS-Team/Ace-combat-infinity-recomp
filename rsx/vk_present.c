#include "vk_present.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SDL3/SDL.h>
#include <SDL3/SDL_vulkan.h>
#include <vulkan/vulkan.h>

static int              g_state = 0;
static SDL_Window*      g_win;
static void pad_init(void);
static void aout_init(void);
static VkInstance       g_inst;
static VkSurfaceKHR     g_surf;
static VkPhysicalDevice g_pdev;
static VkDevice         g_dev;
static uint32_t         g_qfam;
static VkQueue          g_q;
static int              g_mirror_clamp;
#define NPFRAME 2
static VkCommandPool    g_cmdpool;
static VkCommandBuffer  g_cmd[NPFRAME];
static VkFence          g_fence[NPFRAME];
static int              g_pf;
static int              g_pf_used[NPFRAME];
static VkSemaphore      g_sem_acq[NPFRAME];
static VkSemaphore      g_sem_done[8];

static VkSwapchainKHR   g_swap;
static VkFormat         g_swap_fmt;
static VkExtent2D       g_swap_ext;
static uint32_t         g_swap_n;
static VkImage          g_swap_img[8];

static VkBuffer         g_stage_buf;
static VkDeviceMemory   g_stage_mem;
static void*            g_stage_ptr;
static VkDeviceSize     g_stage_size;
static VkImage          g_src_img;
static VkDeviceMemory   g_src_mem;
static uint32_t         g_src_w, g_src_h;

#define VKCHK(x) do{ VkResult _r=(x); if(_r!=VK_SUCCESS){ \
    fprintf(stderr,"[RSXVK] %s -> %d (%s:%d)\n",#x,(int)_r,__FILE__,__LINE__); return 0; } }while(0)

static uint32_t find_mem_type(uint32_t bits, VkMemoryPropertyFlags want){
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(g_pdev,&mp);
    for(uint32_t i=0;i<mp.memoryTypeCount;i++)
        if((bits&(1u<<i)) && (mp.memoryTypes[i].propertyFlags&want)==want) return i;
    return UINT32_MAX;
}

static int create_swapchain(void){
    VkSurfaceCapabilitiesKHR caps;
    VKCHK(vkGetPhysicalDeviceSurfaceCapabilitiesKHR(g_pdev,g_surf,&caps));
    VkExtent2D ext = caps.currentExtent;
    if(ext.width==UINT32_MAX){ int w,h; SDL_GetWindowSizeInPixels(g_win,&w,&h);
        ext.width=(uint32_t)w; ext.height=(uint32_t)h; }
    if(ext.width==0||ext.height==0) return 0;

    uint32_t nfmt=0; VkSurfaceFormatKHR fmts[64];
    vkGetPhysicalDeviceSurfaceFormatsKHR(g_pdev,g_surf,&nfmt,NULL);
    if(nfmt>64) nfmt=64;
    vkGetPhysicalDeviceSurfaceFormatsKHR(g_pdev,g_surf,&nfmt,fmts);
    VkSurfaceFormatKHR pick=fmts[0];
    for(uint32_t i=0;i<nfmt;i++)
        if(fmts[i].format==VK_FORMAT_B8G8R8A8_UNORM){ pick=fmts[i]; break; }

    uint32_t nimg = caps.minImageCount+1;
    if(caps.maxImageCount && nimg>caps.maxImageCount) nimg=caps.maxImageCount;

    VkSwapchainKHR old=g_swap;
    VkSwapchainCreateInfoKHR sci={ .sType=VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR,
        .surface=g_surf, .minImageCount=nimg, .imageFormat=pick.format,
        .imageColorSpace=pick.colorSpace, .imageExtent=ext, .imageArrayLayers=1,
        .imageUsage=VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .imageSharingMode=VK_SHARING_MODE_EXCLUSIVE,
        .preTransform=caps.currentTransform,
        .compositeAlpha=VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
        .presentMode=VK_PRESENT_MODE_FIFO_KHR, .clipped=VK_TRUE, .oldSwapchain=old };
    VKCHK(vkCreateSwapchainKHR(g_dev,&sci,NULL,&g_swap));
    if(old) vkDestroySwapchainKHR(g_dev,old,NULL);
    g_swap_fmt=pick.format; g_swap_ext=ext;
    uint32_t navail=0;
    vkGetSwapchainImagesKHR(g_dev,g_swap,&navail,NULL);
    if(!navail){ fprintf(stderr,"[RSXVK] swapchain reports 0 images\n"); return 0; }
    if(navail>(uint32_t)(sizeof g_swap_img/sizeof g_swap_img[0]))
        navail=(uint32_t)(sizeof g_swap_img/sizeof g_swap_img[0]);
    g_swap_n=navail;
    VkResult gr=vkGetSwapchainImagesKHR(g_dev,g_swap,&g_swap_n,g_swap_img);
    if(gr!=VK_SUCCESS&&gr!=VK_INCOMPLETE){
        fprintf(stderr,"[RSXVK] vkGetSwapchainImagesKHR -> %d\n",(int)gr); return 0; }
    vkDeviceWaitIdle(g_dev);
    for(int i=0;i<NPFRAME;i++){
        if(g_sem_acq[i]) vkDestroySemaphore(g_dev,g_sem_acq[i],NULL);
        g_sem_acq[i]=VK_NULL_HANDLE;
        g_pf_used[i]=0;
    }
    for(uint32_t i=0;i<8;i++){
        if(g_sem_done[i]) vkDestroySemaphore(g_dev,g_sem_done[i],NULL);
        g_sem_done[i]=VK_NULL_HANDLE;
    }
    VkSemaphoreCreateInfo semci={.sType=VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
    for(int i=0;i<NPFRAME;i++)
        VKCHK(vkCreateSemaphore(g_dev,&semci,NULL,&g_sem_acq[i]));
    for(uint32_t i=0;i<g_swap_n;i++)
        VKCHK(vkCreateSemaphore(g_dev,&semci,NULL,&g_sem_done[i]));
    fprintf(stderr,"[RSXVK] swapchain %ux%u fmt=%d n=%u\n",
            ext.width,ext.height,(int)g_swap_fmt,g_swap_n);
    return 1;
}

static void present_retire(int i);

static int ensure_src(uint32_t w, uint32_t h){
    if(g_src_img && g_src_w==w && g_src_h==h) return 1;
    vkDeviceWaitIdle(g_dev);
    for(int i=0;i<NPFRAME;i++) if(g_pf_used[i]){
        vkResetFences(g_dev,1,&g_fence[i]); g_pf_used[i]=0; }
    if(g_src_img){ vkDestroyImage(g_dev,g_src_img,NULL); vkFreeMemory(g_dev,g_src_mem,NULL);
                   g_src_img=VK_NULL_HANDLE; }
    VkDeviceSize need=(VkDeviceSize)w*h*4;
    if(need>g_stage_size){
        if(g_stage_buf){ vkDestroyBuffer(g_dev,g_stage_buf,NULL);
                         vkUnmapMemory(g_dev,g_stage_mem); vkFreeMemory(g_dev,g_stage_mem,NULL);
                         g_stage_buf=VK_NULL_HANDLE; g_stage_ptr=NULL;
                         g_stage_size=0; }
        VkBufferCreateInfo bci={ .sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
            .size=need, .usage=VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
            .sharingMode=VK_SHARING_MODE_EXCLUSIVE };
        VKCHK(vkCreateBuffer(g_dev,&bci,NULL,&g_stage_buf));
        VkMemoryRequirements mr; vkGetBufferMemoryRequirements(g_dev,g_stage_buf,&mr);
        uint32_t mt=find_mem_type(mr.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if(mt==UINT32_MAX) return 0;
        VkMemoryAllocateInfo mai={ .sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
            .allocationSize=mr.size, .memoryTypeIndex=mt };
        VKCHK(vkAllocateMemory(g_dev,&mai,NULL,&g_stage_mem));
        VKCHK(vkBindBufferMemory(g_dev,g_stage_buf,g_stage_mem,0));
        VKCHK(vkMapMemory(g_dev,g_stage_mem,0,VK_WHOLE_SIZE,0,&g_stage_ptr));
        g_stage_size=need;
    }
    VkImageCreateInfo ici={ .sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .imageType=VK_IMAGE_TYPE_2D, .format=VK_FORMAT_B8G8R8A8_UNORM,
        .extent={w,h,1}, .mipLevels=1, .arrayLayers=1,
        .samples=VK_SAMPLE_COUNT_1_BIT, .tiling=VK_IMAGE_TILING_OPTIMAL,
        .usage=VK_IMAGE_USAGE_TRANSFER_SRC_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .sharingMode=VK_SHARING_MODE_EXCLUSIVE,
        .initialLayout=VK_IMAGE_LAYOUT_UNDEFINED };
    VKCHK(vkCreateImage(g_dev,&ici,NULL,&g_src_img));
    VkMemoryRequirements mr; vkGetImageMemoryRequirements(g_dev,g_src_img,&mr);
    uint32_t mt=find_mem_type(mr.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if(mt==UINT32_MAX) return 0;
    VkMemoryAllocateInfo mai={ .sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize=mr.size, .memoryTypeIndex=mt };
    VKCHK(vkAllocateMemory(g_dev,&mai,NULL,&g_src_mem));
    VKCHK(vkBindImageMemory(g_dev,g_src_img,g_src_mem,0));
    g_src_w=w; g_src_h=h;
    return 1;
}

int rsxvk_init(void){
    if(g_state) return g_state>0;
    g_state=-1;
    if(!SDL_Init(SDL_INIT_VIDEO)){
        fprintf(stderr,"[RSXVK] SDL_Init: %s\n",SDL_GetError()); return 0; }
    pad_init();
    aout_init();
    g_win=SDL_CreateWindow("Ace Combat Infinity (recomp)",1280,720,
                           SDL_WINDOW_VULKAN|SDL_WINDOW_RESIZABLE);
    if(!g_win){ fprintf(stderr,"[RSXVK] CreateWindow: %s\n",SDL_GetError()); return 0; }

    Uint32 next=0;
    const char* const* sdlext=SDL_Vulkan_GetInstanceExtensions(&next);
    if(!sdlext){ fprintf(stderr,"[RSXVK] GetInstanceExtensions: %s\n",SDL_GetError()); return 0; }
    const char* layers[1]; uint32_t nlayers=0;
    if(getenv("PS3_VKVALIDATE")) layers[nlayers++]="VK_LAYER_KHRONOS_validation";
    VkApplicationInfo ai={ .sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName="aci-recomp", .apiVersion=VK_API_VERSION_1_1 };
    VkInstanceCreateInfo ici={ .sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo=&ai, .enabledLayerCount=nlayers, .ppEnabledLayerNames=layers,
        .enabledExtensionCount=next, .ppEnabledExtensionNames=sdlext };
    VKCHK(vkCreateInstance(&ici,NULL,&g_inst));
    if(!SDL_Vulkan_CreateSurface(g_win,g_inst,NULL,&g_surf)){
        fprintf(stderr,"[RSXVK] CreateSurface: %s\n",SDL_GetError()); return 0; }

    uint32_t npd=16; VkPhysicalDevice pds[16];
    VKCHK(vkEnumeratePhysicalDevices(g_inst,&npd,pds));
    if(!npd){ fprintf(stderr,"[RSXVK] no Vulkan devices\n"); return 0; }
    int best=-1, best_score=-1;
    for(uint32_t i=0;i<npd;i++){
        VkPhysicalDeviceProperties pp; vkGetPhysicalDeviceProperties(pds[i],&pp);
        uint32_t nqf=32; VkQueueFamilyProperties qf[32];
        vkGetPhysicalDeviceQueueFamilyProperties(pds[i],&nqf,qf);
        for(uint32_t f=0;f<nqf;f++){
            VkBool32 pres=0;
            vkGetPhysicalDeviceSurfaceSupportKHR(pds[i],f,g_surf,&pres);
            if((qf[f].queueFlags&VK_QUEUE_GRAPHICS_BIT) && pres){
                int score=(pp.deviceType==VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)?2:1;
                if(score>best_score){ best_score=score; best=(int)i; g_qfam=f; }
                break;
            }
        }
    }
    if(best<0){ fprintf(stderr,"[RSXVK] no graphics+present queue\n"); return 0; }
    g_pdev=pds[best];
    { VkPhysicalDeviceProperties pp; vkGetPhysicalDeviceProperties(g_pdev,&pp);
      fprintf(stderr,"[RSXVK] device: %s\n",pp.deviceName); }

    float prio=1.0f;
    VkDeviceQueueCreateInfo qci={ .sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex=g_qfam, .queueCount=1, .pQueuePriorities=&prio };
    const char* devext[4]={ VK_KHR_SWAPCHAIN_EXTENSION_NAME }; uint32_t ndevext=1;
    { uint32_t ne=0;
      if(!vkEnumerateDeviceExtensionProperties(g_pdev,NULL,&ne,NULL)&&ne){
          VkExtensionProperties* ep=(VkExtensionProperties*)malloc(ne*sizeof *ep);
          if(ep&&!vkEnumerateDeviceExtensionProperties(g_pdev,NULL,&ne,ep)){
              for(uint32_t i=0;i<ne;i++)
                  if(!strcmp(ep[i].extensionName,
                             VK_KHR_SAMPLER_MIRROR_CLAMP_TO_EDGE_EXTENSION_NAME)){
                      devext[ndevext++]=VK_KHR_SAMPLER_MIRROR_CLAMP_TO_EDGE_EXTENSION_NAME;
                      g_mirror_clamp=1; break; } }
          free(ep); } }
    if(!g_mirror_clamp)
        fprintf(stderr,"[RSXVK] no VK_KHR_sampler_mirror_clamp_to_edge - GCM "
                       "MIRROR_ONCE wrap modes degrade to clamp\n");
    VkDeviceCreateInfo dci={ .sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount=1, .pQueueCreateInfos=&qci,
        .enabledExtensionCount=ndevext, .ppEnabledExtensionNames=devext };
    VKCHK(vkCreateDevice(g_pdev,&dci,NULL,&g_dev));
    vkGetDeviceQueue(g_dev,g_qfam,0,&g_q);

    VkCommandPoolCreateInfo cpci={ .sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT, .queueFamilyIndex=g_qfam };
    VKCHK(vkCreateCommandPool(g_dev,&cpci,NULL,&g_cmdpool));
    VkCommandBufferAllocateInfo cbai={ .sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool=g_cmdpool, .level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        .commandBufferCount=NPFRAME };
    VKCHK(vkAllocateCommandBuffers(g_dev,&cbai,g_cmd));
    VkFenceCreateInfo fci={ .sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
    for(int i=0;i<NPFRAME;i++) VKCHK(vkCreateFence(g_dev,&fci,NULL,&g_fence[i]));
    if(!create_swapchain()) return 0;
    g_state=1;
    fprintf(stderr,"[RSXVK] init OK\n");
    return 1;
}

VkDevice         rsxvk_device(void){ return g_dev; }
VkPhysicalDevice rsxvk_phys(void){ return g_pdev; }
VkQueue          rsxvk_queue(void){ return g_q; }
uint32_t         rsxvk_qfam(void){ return g_qfam; }
int              rsxvk_have_mirror_clamp(void){ return g_mirror_clamp; }

static void img_barrier(VkCommandBuffer cb, VkImage img,
                        VkImageLayout from, VkImageLayout to,
                        VkAccessFlags src, VkAccessFlags dst){
    VkImageMemoryBarrier b={ .sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=src, .dstAccessMask=dst, .oldLayout=from, .newLayout=to,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED, .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=img, .subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1} };
    vkCmdPipelineBarrier(cb,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,
                         VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,0,0,NULL,0,NULL,1,&b);
}

static void present_retire(int i){
    if(!g_pf_used[i]) return;
    vkWaitForFences(g_dev,1,&g_fence[i],VK_TRUE,UINT64_MAX);
    vkResetFences(g_dev,1,&g_fence[i]);
    g_pf_used[i]=0;
}

static void present_from(VkImage srcimg, uint32_t w, uint32_t h, int upload){
    int slot=g_pf;
    present_retire(slot);
    uint32_t idx=0;
    VkResult r=vkAcquireNextImageKHR(g_dev,g_swap,UINT64_MAX,g_sem_acq[slot],
                                     VK_NULL_HANDLE,&idx);
    if(r==VK_ERROR_OUT_OF_DATE_KHR){ vkDeviceWaitIdle(g_dev);
        if(!create_swapchain()) g_state=-1; return; }
    if(r!=VK_SUCCESS && r!=VK_SUBOPTIMAL_KHR){
        fprintf(stderr,"[RSXVK] acquire -> %d\n",(int)r); return; }
    if(idx>=8){ fprintf(stderr,"[RSXVK] swapchain image index %u out of range\n",idx);
        return; }

    VkCommandBuffer cb=g_cmd[slot];
    vkResetCommandBuffer(cb,0);
    VkCommandBufferBeginInfo bi={ .sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT };
    vkBeginCommandBuffer(cb,&bi);

    if(upload){
        img_barrier(cb,g_src_img,VK_IMAGE_LAYOUT_UNDEFINED,
                    VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,0,VK_ACCESS_TRANSFER_WRITE_BIT);
        VkBufferImageCopy bic={ .imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
            .imageExtent={w,h,1} };
        vkCmdCopyBufferToImage(cb,g_stage_buf,g_src_img,
                               VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&bic);
        img_barrier(cb,g_src_img,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                    VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                    VK_ACCESS_TRANSFER_WRITE_BIT,VK_ACCESS_TRANSFER_READ_BIT);
    }
    img_barrier(cb,g_swap_img[idx],VK_IMAGE_LAYOUT_UNDEFINED,
                VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,0,VK_ACCESS_TRANSFER_WRITE_BIT);
    uint32_t dw=g_swap_ext.width, dh=g_swap_ext.height;
    uint32_t bw=dw, bh=dw*h/w;
    if(bh>dh){ bh=dh; bw=dh*w/h; }
    int32_t x0=(int32_t)(dw-bw)/2, y0=(int32_t)(dh-bh)/2;
    if(bw<dw||bh<dh){
        VkClearColorValue black={{0,0,0,1}};
        VkImageSubresourceRange rng={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
        vkCmdClearColorImage(cb,g_swap_img[idx],
                             VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&black,1,&rng);
    }
    VkImageBlit blit={ .srcSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
        .srcOffsets={{0,0,0},{(int32_t)w,(int32_t)h,1}},
        .dstSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
        .dstOffsets={{x0,y0,0},{x0+(int32_t)bw,y0+(int32_t)bh,1}} };
    vkCmdBlitImage(cb,srcimg,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                   g_swap_img[idx],VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                   1,&blit,VK_FILTER_LINEAR);
    img_barrier(cb,g_swap_img[idx],VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,VK_ACCESS_TRANSFER_WRITE_BIT,0);
    vkEndCommandBuffer(cb);

    VkPipelineStageFlags wait_stage=VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo si={ .sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .waitSemaphoreCount=1, .pWaitSemaphores=&g_sem_acq[slot],
        .pWaitDstStageMask=&wait_stage,
        .commandBufferCount=1, .pCommandBuffers=&cb,
        .signalSemaphoreCount=1, .pSignalSemaphores=&g_sem_done[idx] };
    vkQueueSubmit(g_q,1,&si,g_fence[slot]);
    g_pf_used[slot]=1;
    VkPresentInfoKHR pi={ .sType=VK_STRUCTURE_TYPE_PRESENT_INFO_KHR,
        .waitSemaphoreCount=1, .pWaitSemaphores=&g_sem_done[idx],
        .swapchainCount=1, .pSwapchains=&g_swap, .pImageIndices=&idx };
    r=vkQueuePresentKHR(g_q,&pi);
    g_pf=(slot+1)%NPFRAME;
    if(r==VK_ERROR_OUT_OF_DATE_KHR||r==VK_SUBOPTIMAL_KHR){
        vkDeviceWaitIdle(g_dev);
        for(int i=0;i<NPFRAME;i++) if(g_pf_used[i]){
            vkResetFences(g_dev,1,&g_fence[i]); g_pf_used[i]=0; }
        if(!create_swapchain()) g_state=-1;
    }
}

static SDL_Gamepad*   g_pad;
static SDL_JoystickID g_pad_id;
static int            g_pad_up;

static int pad_wanted(SDL_JoystickID id){
    SDL_GamepadType t=SDL_GetGamepadTypeForID(id);
    return t!=SDL_GAMEPAD_TYPE_XBOX360 && t!=SDL_GAMEPAD_TYPE_XBOXONE;
}
static void pad_try_open(SDL_JoystickID id){
    if(g_pad || !pad_wanted(id)) return;
    SDL_Gamepad* g=SDL_OpenGamepad(id);
    if(!g){ fprintf(stderr,"[PAD] SDL could not open '%s': %s\n",
                    SDL_GetGamepadNameForID(id),SDL_GetError()); return; }
    g_pad=g; g_pad_id=id;
    fprintf(stderr,"[PAD] SDL gamepad connected: '%s' (%s, %04x:%04x)\n",
            SDL_GetGamepadName(g),SDL_GetGamepadStringForType(SDL_GetGamepadType(g)),
            SDL_GetGamepadVendor(g),SDL_GetGamepadProduct(g));
}
static void pad_open_any(void){
    int n=0; SDL_JoystickID* ids=SDL_GetGamepads(&n);
    for(int i=0;ids && i<n && !g_pad;i++) pad_try_open(ids[i]);
    SDL_free(ids);
}
static void pad_init(void){
    SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS,"1");
    if(!SDL_InitSubSystem(SDL_INIT_GAMEPAD)){
        fprintf(stderr,"[PAD] SDL gamepad support unavailable: %s\n",SDL_GetError()); return; }
    g_pad_up=1;
    SDL_LockJoysticks(); pad_open_any(); SDL_UnlockJoysticks();
}
static void pad_event(const SDL_Event* e){
    if(!g_pad_up) return;
    if(e->type==SDL_EVENT_GAMEPAD_ADDED){
        SDL_LockJoysticks(); pad_try_open(e->gdevice.which); SDL_UnlockJoysticks();
    } else if(e->type==SDL_EVENT_GAMEPAD_REMOVED){
        SDL_LockJoysticks();
        if(g_pad && e->gdevice.which==g_pad_id){
            fprintf(stderr,"[PAD] SDL gamepad disconnected\n");
            SDL_CloseGamepad(g_pad); g_pad=NULL; g_pad_id=0;
            pad_open_any();
        }
        SDL_UnlockJoysticks();
    }
}
int rsxvk_pad_read(RsxvkPad* o){
    if(!g_pad_up || !o) return 0;
    int ok=0;
    SDL_LockJoysticks();
    if(g_pad){
        SDL_UpdateGamepads();
        SDL_Gamepad* g=g_pad;
        #define B(b) SDL_GetGamepadButton(g,SDL_GAMEPAD_BUTTON_##b)
        uint16_t d1=0,d2=0;
        if(B(BACK))           d1|=1u<<0;
        if(B(LEFT_STICK))     d1|=1u<<1;
        if(B(RIGHT_STICK))    d1|=1u<<2;
        if(B(START))          d1|=1u<<3;
        if(B(DPAD_UP))        d1|=1u<<4;
        if(B(DPAD_RIGHT))     d1|=1u<<5;
        if(B(DPAD_DOWN))      d1|=1u<<6;
        if(B(DPAD_LEFT))      d1|=1u<<7;
        if(B(LEFT_SHOULDER))  d2|=1u<<2;
        if(B(RIGHT_SHOULDER)) d2|=1u<<3;
        if(B(NORTH))          d2|=1u<<4;
        if(B(EAST))           d2|=1u<<5;
        if(B(SOUTH))          d2|=1u<<6;
        if(B(WEST))           d2|=1u<<7;
        #undef B
        int tl=SDL_GetGamepadAxis(g,SDL_GAMEPAD_AXIS_LEFT_TRIGGER);
        int tr=SDL_GetGamepadAxis(g,SDL_GAMEPAD_AXIS_RIGHT_TRIGGER);
        if(tl<0) tl=0; if(tr<0) tr=0;
        o->l2=(uint8_t)(tl>>7); o->r2=(uint8_t)(tr>>7);
        if(o->l2>30) d2|=1u<<0;
        if(o->r2>30) d2|=1u<<1;
        int ly=-(int)SDL_GetGamepadAxis(g,SDL_GAMEPAD_AXIS_LEFTY);
        int ry=-(int)SDL_GetGamepadAxis(g,SDL_GAMEPAD_AXIS_RIGHTY);
        if(ly>32767) ly=32767; if(ry>32767) ry=32767;
        o->lx=SDL_GetGamepadAxis(g,SDL_GAMEPAD_AXIS_LEFTX);  o->ly=(int16_t)ly;
        o->rx=SDL_GetGamepadAxis(g,SDL_GAMEPAD_AXIS_RIGHTX); o->ry=(int16_t)ry;
        o->d1=d1; o->d2=d2;
        ok=1;
    }
    SDL_UnlockJoysticks();
    return ok;
}

static volatile int     g_aout_up;
static SDL_AudioStream* g_aout;
static int              g_aout_failed;

static void aout_init(void){
    const char* e=getenv("PS3_AUDIO");
    if(e && e[0]=='0'){ fprintf(stderr,"[AUDIO] host output disabled (PS3_AUDIO=0)\n"); return; }
    if(!SDL_InitSubSystem(SDL_INIT_AUDIO)){
        fprintf(stderr,"[AUDIO] SDL audio unavailable: %s\n",SDL_GetError()); return; }
    g_aout_up=1;
}
int rsxvk_audio_push(const float* frames, int nframes){
    if(!g_aout_up || g_aout_failed) return -1;
    if(!g_aout){
        SDL_AudioSpec spec; spec.format=SDL_AUDIO_F32; spec.channels=8; spec.freq=48000;
        g_aout=SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK,&spec,NULL,NULL);
        if(!g_aout){ g_aout_failed=1;
            fprintf(stderr,"[AUDIO] could not open the default playback device: %s\n",SDL_GetError());
            return -1; }
        SDL_AudioSpec dev; int dframes=0;
        if(SDL_GetAudioDeviceFormat(SDL_GetAudioStreamDevice(g_aout),&dev,&dframes))
            fprintf(stderr,"[AUDIO] output: '%s' %d Hz, %d ch, device buffer %d frames "
                    "(fed 48000 Hz, 8 ch float)\n",
                    SDL_GetAudioDeviceName(SDL_GetAudioStreamDevice(g_aout)),
                    dev.freq,dev.channels,dframes);
        SDL_ResumeAudioStreamDevice(g_aout);
    }
    if(nframes>0) SDL_PutAudioStreamData(g_aout,frames,nframes*8*(int)sizeof(float));
    int q=SDL_GetAudioStreamQueued(g_aout);
    return q<0 ? 0 : q/(8*(int)sizeof(float));
}
void rsxvk_audio_ratio(float ratio){ if(g_aout) SDL_SetAudioStreamFrequencyRatio(g_aout,ratio); }
void rsxvk_audio_clear(void){ if(g_aout) SDL_ClearAudioStream(g_aout); }

static void pump_events(void){
    SDL_Event e;
    while(SDL_PollEvent(&e)){
        if(e.type==SDL_EVENT_QUIT){ fprintf(stderr,"[RSXVK] window closed, exiting\n"); exit(0); }
        pad_event(&e);
    }
}

void rsxvk_set_title(const char* s){
    if(g_state<=0||!g_win||!s) return;
    SDL_SetWindowTitle(g_win,s);
}

int rsxvk_has_focus(void){
    if(g_state<=0||!g_win) return 0;
    return (SDL_GetWindowFlags(g_win)&SDL_WINDOW_INPUT_FOCUS)!=0;
}

void rsxvk_pump_tick(void){
    if(g_state<=0) return;
    static Uint64 last;
    Uint64 now=SDL_GetTicks();
    if(now-last<100) return;
    last=now;
    pump_events();
}

void rsxvk_present(const uint8_t* src, uint32_t w, uint32_t h, uint32_t pitch){
    if(g_state<=0) return;
    pump_events();
    if(!src||!w||!h) return;
    if(w>4096||h>4096) return;
    if(!ensure_src(w,h)) { g_state=-1; return; }
    present_retire(g_pf);
    for(uint32_t y=0;y<h;y++){
        const uint32_t* s=(const uint32_t*)(src+(size_t)y*pitch);
        uint32_t* d=(uint32_t*)((uint8_t*)g_stage_ptr+(size_t)y*w*4);
        for(uint32_t x=0;x<w;x++) d[x]=__builtin_bswap32(s[x]);
    }
    present_from(g_src_img,w,h,1);
}

void rsxvk_present_image(VkImage img, uint32_t w, uint32_t h){
    if(g_state<=0) return;
    pump_events();
    present_from(img,w,h,0);
}
