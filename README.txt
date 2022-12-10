Please first ensure that the CPU on your device is newer than
the 6th generation (Skylake), and that the SGX feature is 
fully enabled by the BIOS settings. 
Also, to run the application, you need to install Intel's 
SGX SDK and SGX drivers for the Linux OS.
------------------------
Purpose of SampleEnclave
------------------------
The project demonstrates several fundamental usages of Intel(R) Software Guard 
Extensions (Intel(R) SGX) SDK:
- Initializing and destroying an enclave
- Creating ECALLs or OCALLs

- Calling trusted libraries inside the enclave

------------------------
Build our project
-----------------------
To build our project, you may need to first install Intel SGX SDK for Linux system.
Also, you may also need to set the environment for the SGX SDK so that you can properly build the enclave:

source <SGX_PATH>/sgxsdk/environment
In addition, you should manually set the correct path for mysql in Makefile.

Build all:
make clean
make all


------------------------------------
Execute our project
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
3. Build the project with the prepared Makefile:
    
    make install

------------------------------------------
Explanation about Configuration Parameters
------------------------------------------
TCSMaxNum, TCSNum, TCSMinPool

    These three parameters will determine whether a thread will be created
    dynamically  when there is no available thread to do the work.


StackMaxSize, StackMinSize

    For a dynamically created thread, StackMinSize is the amount of stack available
    once the thread is created and StackMaxSize is the total amount of stack that
    thread can use. The gap between StackMinSize and StackMaxSize is the stack
    dynamically expanded as necessary at runtime.

    For a static thread, only StackMaxSize is relevant which specifies the total
    amount of stack available to the thread.


HeapMaxSize, HeapInitSize, HeapMinSize

    HeapMinSize is the amount of heap available once the enclave is initialized.

    HeapMaxSize is the total amount of heap an enclave can use. The gap between
    HeapMinSize and HeapMaxSize is the heap dynamically expanded as necessary
    at runtime.

    HeapInitSize is here for compatibility.

-------------------------------------------------    
Sample configuration files for the Sample Enclave
-------------------------------------------------
config.01.xml: There is no dynamic thread, no dynamic heap expansion.
config.02.xml: There is no dynamic thread. But dynamic heap expansion can happen.
config.03.xml: There are dynamic threads. For a dynamic thread, there's no stack expansion.
config.04.xml: There are dynamic threads. For a dynamic thread, stack will expanded as necessary.

-------------------------------------------------
Launch token initialization
-------------------------------------------------
If using libsgx-enclave-common or sgxpsw under version 2.4, an initialized variable launch_token needs to be passed as the 3rd parameter of API sgx_create_enclave. For example,

sgx_launch_token_t launch_token = {0};
sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, launch_token, NULL, &global_eid, NULL);
