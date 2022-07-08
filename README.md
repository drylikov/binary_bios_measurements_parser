# binary_bios_measurements_parser
Linux TPM Trusted Boot binary_bios_measurements file parser/reconstructor.

### Information
This small script prints Trusted Platform Module binary_bios_measurements file contents used in Trusted Boot cycle, and allows you to replace measure events with supplied hash values to reconstruct final PCR values state with modified events list.

### Usage
This script was written to reconstruct PCR state of [Namco Nirin game](https://medium.com/p/1f8423fdeb3b/) in order to decrypt the game file.

It could be handy for update system for PC with Trusted Boot to determine PCR state of updated kernel or initramfs images if the system has been updated but not rebooted yet.
