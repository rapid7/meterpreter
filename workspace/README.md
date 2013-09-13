Intro
=====

This repo/branch is where work is being done to bring Metepreter up to speed with new
toolsets, and to tidy it up and make more fitting for public consumption. This is very
much a work in progress and hence the code will be rather turbulent and unstable until
the changes start to settle and proper testing is put in place.

In Development
==============

Known Issues
------------

1. Lots of warnings still present in both 32 and 64 bit builds.
1. Most of the `mimikatz` extension methods come back with errors on x64.

Things to do
------------

* Improve the speed of the build.
* Improve (reduce) the size of the binaries.
* Start working on a unit/functional testing strategy.

Build Requirements
==================

Meterpreter can be built with [Visual Studio 2012 Express for Desktop][vs_express] or any
paid version of [Visual Studio 2012][vs_paid]. Earlier toolsets on Windows are no longer
supported.

Visual Studio 2012 requires .NET 4.5 in order to run, and as a result isn't compatible
with Windows XP due to the fact that .NET 4.5 will not run on Windows XP. However, this
does not mean that Metepreter itself will not run on Windows XP, it just means that it's
not possible to _build_ it on Windows XP.

Visual Studio 2012 Express
--------------------------

In order to build successfully with this version of Visual Studio you must first make sure
that the most recent updates have been applied. At the time of writing, the latest known
update is **Update 3**. Without this update you won't be able to build.

Running the Build
=================

Open up a Visual Studio command prompt by selecting it in the Start menu, or alternatively
you can manually run `vcvars32.bat` from an existing command line.

Once you have your environment variables set up, change to the root folder where the
meterpreter source is located. From here you can:

* Build the x86 version by running: `make x86`
* Build the x64 version by running: `make x64`
* Build both x86 and x64 versions by running: `make`

  [vs_express]: http://www.microsoft.com/visualstudio/eng/downloads#d-2012-express
  [vs_paid]: http://www.microsoft.com/visualstudio/eng/downloads#d-2012-editions