//===-- NativeRegisterContextFreeBSD_arm64.h --------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__aarch64__)

#ifndef lldb_NativeRegisterContextFreeBSD_arm64_h
#define lldb_NativeRegisterContextFreeBSD_arm64_h

// clang-format off
#include <sys/types.h>
#include <sys/param.h>
#include <machine/reg.h>
// clang-format on

#include "Plugins/Process/FreeBSD/NativeRegisterContextFreeBSD.h"
#include "Plugins/Process/Utility/NativeRegisterContextDBReg_arm64.h"
#include "Plugins/Process/Utility/RegisterInfoPOSIX_arm64.h"

#include <array>

#if __FreeBSD_version >= 1300139
#  define LLDB_HAS_FREEBSD_WATCHPOINT 1
#endif

namespace lldb_private {
namespace process_freebsd {

class NativeProcessFreeBSD;

class NativeRegisterContextFreeBSD_arm64
    : public NativeRegisterContextFreeBSD,
      public NativeRegisterContextDBReg_arm64 {
public:
  NativeRegisterContextFreeBSD_arm64(
      const ArchSpec &target_arch,
      NativeThreadProtocol &native_thread,
      std::unique_ptr<RegisterInfoPOSIX_arm64> register_info_up);

  uint32_t GetRegisterSetCount() const override;

  uint32_t GetUserRegisterCount() const override;

  const RegisterSet *GetRegisterSet(uint32_t set_index) const override;

  Status ReadRegister(const RegisterInfo *reg_info,
                      RegisterValue &reg_value) override;

  Status WriteRegister(const RegisterInfo *reg_info,
                       const RegisterValue &reg_value) override;

  Status ReadAllRegisterValues(lldb::DataBufferSP &data_sp) override;

  Status WriteAllRegisterValues(const lldb::DataBufferSP &data_sp) override;

  llvm::Error
  CopyHardwareWatchpointsFrom(NativeRegisterContextFreeBSD &source) override;

private:
  // Due to alignment, FreeBSD reg/fpreg are a few bytes larger than
  // LLDB's GPR/FPU structs.  However, all fields have matching offsets
  // and sizes, so we do not have to worry about these (and we have
  // a unittest to assert that).
  std::array<uint8_t, sizeof(reg)> m_reg_data;
  std::array<uint8_t, sizeof(fpreg)> m_fpreg_data;

  struct arm64_addr_mask {
    uint64_t data_mask;
    uint64_t insn_mask;
  };

  bool m_addr_mask_is_valid;
  struct arm64_addr_mask m_addr_mask;

#ifdef LLDB_HAS_FREEBSD_WATCHPOINT
  dbreg m_dbreg;
  bool m_read_dbreg;
#endif

  void *GetGPRBuffer() { return &m_reg_data; }
  size_t GetGPRBufferSize() { return sizeof(m_reg_data); }

  void *GetFPRBuffer() { return &m_fpreg_data; }
  size_t GetFPRSize() { return sizeof(m_fpreg_data); }

  void *GetAddrMaskBuffer() { return &m_addr_mask; }
  size_t GetAddrMaskBufferSize() { return sizeof(m_addr_mask); }

  bool IsGPR(unsigned reg) const;
  bool IsFPR(unsigned reg) const;
  bool IsAddrMask(unsigned reg) const;

  Status ReadGPR();
  Status WriteGPR();
  Status ReadAddrMask();

  Status ReadFPR();
  Status WriteFPR();

  uint32_t CalculateFprOffset(const RegisterInfo *reg_info) const;
  uint32_t CalculateAddrMaskOffset(const RegisterInfo *reg_info) const;

  llvm::Error ReadHardwareDebugInfo() override;
  llvm::Error WriteHardwareDebugRegs(DREGType hwbType) override;

  RegisterInfoPOSIX_arm64 &GetRegisterInfo() const;
};

} // namespace process_freebsd
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextFreeBSD_arm64_h

#endif // defined (__aarch64__)
