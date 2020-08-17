.. SPDX-License-Identifier: GPL-2.0

==============
Devlink Metric
==============

The ``devlink-metric`` mechanism allows device drivers to expose device metrics
to user space in a standard and extensible fashion. It provides an alternative
to the driver-specific debugfs interface.

Metric Types
============

The ``devlink-metric`` mechanism supports the following metric types:

  * ``counter``: Monotonically increasing. Cannot be reset.

Metrics Documentation
=====================

All the metrics exposed by a device driver must be clearly documented in the
driver-specific ``devlink`` documentation under
``Documentation/networking/devlink/``.

When possible, a selftest (under ``tools/testing/selftests/drivers/``) should
also be provided to ensure the metrics are updated under the right conditions.

Testing
=======

See ``tools/testing/selftests/drivers/net/netdevsim/devlink.sh`` for a
test covering the core infrastructure. Test cases should be added for any new
functionality.

Device drivers should focus their tests on device-specific functionality, such
as making sure the exposed metrics are correctly incremented and read from the
device.
