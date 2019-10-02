set(PAL_SYMBOL_LIST
    DkVirtualMemoryAlloc
    DkVirtualMemoryFree
    DkVirtualMemoryProtect
    DkThreadCreate
    DkThreadDelayExecution
    DkThreadYieldExecution
    DkThreadExit
    DkThreadResume
    DkMutexCreate
    DkNotificationEventCreate
    DkSynchronizationEventCreate
    DkMutexRelease
    DkEventSet
    DkEventClear
    DkObjectsWaitAny
    DkStreamOpen
    DkStreamRead
    DkStreamWrite
    DkStreamMap
    DkStreamUnmap
    DkStreamSetLength
    DkStreamFlush
    DkStreamDelete
    DkSendHandle
    DkReceiveHandle
    DkStreamWaitForClient
    DkStreamGetName
    DkStreamAttributesQueryByHandle
    DkStreamAttributesQuery
    DkProcessCreate
    DkProcessExit
    DkProcessSandboxCreate
    DkSystemTimeQuery
    DkRandomBitsRead
    DkInstructionCacheFlush
    DkCpuIdRetrieve
    DkObjectClose
    DkSetExceptionHandler
    DkExceptionReturn
    DkCreatePhysicalMemoryChannel
    DkPhysicalMemoryCommit
    DkPhysicalMemoryMap
    DkSegmentRegister
    DkStreamChangeName
    DkStreamAttributesSetByHandle
    DkMemoryAvailableQuota
    DkDebugAttachBinary
    DkDebugDetachBinary
    pal_printf
    pal_control_addr)

file(READ ${INPUT_FILE} PAL_MAP_TEMPLATE)
string(REPLACE "$(PAL_SYMBOLS)" "${PAL_SYMBOL_LIST};" PAL_MAP "${PAL_MAP_TEMPLATE}")
file(WRITE ${OUTPUT_FILE} "${PAL_MAP}")