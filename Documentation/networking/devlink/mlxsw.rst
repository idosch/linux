.. SPDX-License-Identifier: GPL-2.0

=====================
mlxsw devlink support
=====================

This document describes the devlink features implemented by the ``mlxsw``
device driver.

Parameters
==========

.. list-table:: Generic parameters implemented

   * - Name
     - Mode
   * - ``fw_load_policy``
     - driverinit

The ``mlxsw`` driver also implements the following driver-specific
parameters.

.. list-table:: Driver-specific parameters implemented
   :widths: 5 5 5 85

   * - Name
     - Type
     - Mode
     - Description
   * - ``acl_region_rehash_interval``
     - u32
     - runtime
     - Sets an interval for periodic ACL region rehashes. The value is
       specified in milliseconds, with a minimum of ``3000``. The value of
       ``0`` disables periodic work entirely. The first rehash will be run
       immediately after the value is set.

The ``mlxsw`` driver supports reloading via ``DEVLINK_CMD_RELOAD``

Info versions
=============

The ``mlxsw`` driver reports the following versions

.. list-table:: devlink info versions implemented
   :widths: 5 5 90

   * - Name
     - Type
     - Description
   * - ``hw.revision``
     - fixed
     - The hardware revision for this board
   * - ``fw.psid``
     - fixed
     - Firmware PSID
   * - ``fw.version``
     - running
     - Three digit firmware version

Driver-specific Traps
=====================

.. list-table:: List of Driver-specific Traps Registered by ``mlxsw``
   :widths: 5 5 90

   * - Name
     - Type
     - Description
   * - ``irif_disabled``
     - ``drop``
     - Traps packets that the device decided to drop because they need to be
       routed from a disabled router interface (RIF). This can happen during
       RIF dismantle, when the RIF is first disabled before being removed
       completely
   * - ``erif_disabled``
     - ``drop``
     - Traps packets that the device decided to drop because they need to be
       routed through a disabled router interface (RIF). This can happen during
       RIF dismantle, when the RIF is first disabled before being removed
       completely

Metrics
=======

.. list-table:: List of metrics registered by ``mlxsw``
   :widths: 5 5 20 70

   * - Name
     - Type
     - Supported platforms
     - Description
   * - ``nve_vxlan_encap``
     - ``counter``
     - Spectrum-1 only
     - Counts number of packets that were VXLAN encapsulated by the device. A
       packet sent to multiple VTEPs is counted multiple times
   * - ``nve_vxlan_decap``
     - ``counter``
     - Spectrum-1 only
     - Counts number of VXLAN packets that were decapsulated (successfully or
       otherwise) by the device
   * - ``nve_vxlan_decap_errors``
     - ``counter``
     - Spectrum-1 only
     - Counts number of VXLAN packets that encountered decapsulation errors.
       This includes overlay packets with a VLAN tag, ECN mismatch between
       overlay and underlay, multicast overlay source MAC, overlay source MAC
       equals overlay destination MAC and packets too short to decapsulate
   * - ``nve_vxlan_decap_discards``
     - ``counter``
     - All
     - Counts number of VXLAN packets that were discarded during decapsulation.
       In Spectrum-1 this includes packets that had to be VXLAN decapsulated
       when VXLAN decapsulation is disabled and fragmented overlay packets. In
       Spectrum-2 this includes ``nve_vxlan_decap_errors`` errors and a missing
       mapping between VNI and filtering identifier (FID)
