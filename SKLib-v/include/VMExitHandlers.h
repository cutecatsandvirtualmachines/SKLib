#pragma once

#include "EPT.h"
#include "VTxException.h"

#ifdef _KERNEL_MODE

namespace VTx {
	namespace VMExitHandlers {
        bool HandleCPUID(PREGS pContext);
        bool HandleCR(PREGS pContext);
        bool HandleGDTRIDTR(PREGS pContext);
        bool HandleRDMSR(PREGS pContext);
        bool HandleWRMSR(PREGS pContext);
        bool HandleXSetBv(PREGS pContext);
        bool HandleInvpcid(PREGS pContext);
    }
}

#endif