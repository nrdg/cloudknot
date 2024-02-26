v0.6 (February 26, 2024)
==========================
  * BF: Update docker setup and dependencies (#307)

v0.5.3 (February 03, 2022)
==========================
  * DOC: Update minimal required permissions (#302)
  * BF: Use separate cloudformation templates for gpu jobs (#299)

v0.5.2 (November 17, 2021)
==========================
  * ENH: Allow user to set number of GPUs for each job (#295)
  * Use boto3 to get valid ec2 instance types (#284)
  * Allow longer names for knots and fail earlier if they are too long (#282)

v0.5.1 (March 27, 2021)
=======================
  * ENH: Add nocache option to DockerImage.build() (#278)
  * ENH: Add option to remove version pinning from pip requirements file (#277)
  * FIX: Use default pickle protocol even for cloudpickle (#273)
  * ENH: Add --ignore-installed option to ck.DockerImage (#275)
  * ENH: Remove six (#274)

v0.5.0 (December 23, 2020)
==========================
  * FIX: Windows carriage return (#268)
  * FIX: Allow user to specify name for new DockerImage instances (#265)
  * ENH: Enforce maximum name length for Pars and Knot (#263)
  * ENH: Automatically set job_type in knot.map() by inspecting the length of the arguments. (#261)
  * FIX: Require object names to conform to AWS URI regex (#260)
  * Add functions to clean up the cloudknot config file (#250)
  * [ENH] Improve AWS resource tagging and allow user to provide custom tags (#249)
  * Test Job Definition Name (#246)

v0.4.2 (July 24, 2020)
======================
  * Remove config files for services we no longer use (#244)
  * Create a better release message (#243)
  * WIP: Fix zenodo metadata (#241)
  * Use relative paths in docbuild.yml (#242)


v0.4.1 (July 24, 2020)
======================
  * Allow user to refresh function for existing DockerImage (#240)
  * Code style improvement suggestions from codacy (#237)
  * Add publish_release script (#238)
  * Add citation info to docs and update README badges (#236)
  * Add back tags and use repo URI not image URI (#235)
  * Adds some tools for maintenance. (#232)
  * Update setup.py URL and bump version (#229)
  * Fix volume_size and PARS policies issues (#233)


