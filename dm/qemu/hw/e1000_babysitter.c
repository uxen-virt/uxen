
#include <dm/qemu_glue.h>

#include "e1000_babysitter.h"

#include "e1000_hw.h"


#define ADDR_TO_RN(a) ((a)>>2)

#define N_R ADDR_TO_RN(0x408)

static const uint32_t interesting_if_changed[N_R] = {
  [ADDR_TO_RN (E1000_CTRL)] =
    E1000_CTRL_LRST | E1000_CTRL_FORCE_PHY_RESET | E1000_CTRL_RST,
  [ADDR_TO_RN (E1000_TCTL)] = E1000_TCTL_EN | E1000_TCTL_RST,
  [ADDR_TO_RN (E1000_RCTL)] = E1000_RCTL_EN | E1000_RCTL_RST,
};

static const uint32_t interesting_if_set[N_R] = {
  [ADDR_TO_RN (E1000_CTRL)] =
    E1000_CTRL_LRST | E1000_CTRL_FORCE_PHY_RESET | E1000_CTRL_RST,
  [ADDR_TO_RN (E1000_TCTL)] = E1000_TCTL_RST,
  [ADDR_TO_RN (E1000_RCTL)] = E1000_RCTL_RST,
};

static const uint32_t interesting_if_unset[N_R] = {
};

static uint32_t regs[N_R];


#define N_PHY_R 1


static const uint16_t phy_interesting_if_changed[N_PHY_R] = {
  [PHY_CTRL] = MII_CR_AUTO_NEG_EN | MII_CR_POWER_DOWN | MII_CR_RESET,
};

static const uint16_t phy_interesting_if_set[N_R] = {
  [PHY_CTRL] = MII_CR_RESET,
};

static const uint16_t phy_interesting_if_unset[N_R] = {
};


static uint16_t phy_regs[N_PHY_R];

void
e1000_babysitter (uint32_t reg, uint32_t val)
{
  int interesting = 0;
  int rn;

  rn = ADDR_TO_RN (reg);
  if (rn >= N_R)
    return;

  if (val & interesting_if_set[rn])
    interesting++;
  if ((val ^ regs[rn]) & interesting_if_changed[rn])
    interesting++;
  if (~val & interesting_if_unset[rn])
    interesting++;

  if (interesting) {
    debug_printf("%s: reg 0x%04x 0x%08x->0x%08x\n", __FUNCTION__,
                 reg, val, regs[rn]);
  };

  regs[rn] = val;
}



void
e1000_babysitter_phy (uint32_t rn, uint16_t val)
{
  int interesting = 0;

  if (rn >= N_PHY_R)
    return;

  if (val & phy_interesting_if_set[rn])
    interesting++;
  if ((val ^ phy_regs[rn]) & phy_interesting_if_changed[rn])
    interesting++;
  if (~val & phy_interesting_if_unset[rn])
    interesting++;

  if (interesting) {
    debug_printf("%s: reg 0x%02x 0x%04x->0x%04x\n", __FUNCTION__,
                 rn, val, phy_regs[rn]);
  };

  phy_regs[rn] = val;
}


void
e1000_babysitter_link (int up)
{
  debug_printf("%s: link electively set %s\n", __FUNCTION__,
               up ? "up" : "down");
}

void
e1000_babysitter_autoneg_done (void)
{
  debug_printf("%s\n", __FUNCTION__);
}
