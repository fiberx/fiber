# fiber

Source-binary patch presence test system.

## 0x0 A Simple Workflow

We will briefly explain fiber's workflow here with the examples under *examples* folder. Basically, we prepared some security patches under *examples/patches* folder, our reference kernel *examples/imgs/angler_img_20170513* adopts all these patches but *examples/imgs/angler_img_20160513* does not. We then generate binary signatures (stored in *examples/sigs*) for these patches and then use them to test the patch presence for the target kernel (*examples/imgs/image-G9300-160909*, Samsung S7 kernel released in 2016/09/09). The test result can be found in *examples/match_res_image-G9300-160909_1528162862_m1* where **P** means the related patch has been adopted and **N** otherwise.

**Step 0**  
Use the picker (section 0x2) to analyze the patches and the reference source code in order to pick out
most suitable change sites introduced by the patch. Our reference kernel source code (patched) is [kernel-msm-src](https://android.googlesource.com/kernel/msm/) with commit cedc139f61870d3f4f8a80f9030b0836b56e2204.

**Step 1**  
Translate each change site identified by the picker to a binary signature with the translator (section 0x3).

**Step 2**  
Validate the generated binary signatures by trying to match them in both reference unpatched and patched kernels.
This can be done with the matcher in mode 0 (section 0x4). 
The mode 0 matching result can then be analyzed by "res_analyzer" (section 5.2), who will generate the 
mode 1 matching list (section 0x4) that is required for the real patch presence test for target kernels.
If for a specific patch there are no valid binary signatures (see section 5.2), we need to re-start from step 0 to pick more change sites
or even manually specify some change sites.

**Step 3**  
Use the valid binary signatures to do patch presence test for the target kernels with the matcher's mode 1. (section 0x4)

## 0x1 Environment Setup

At first we need to install virtualenvwrapper for python, please follow the [official installation instructions](http://virtualenvwrapper.readthedocs.io/en/latest/install.html).
Before continuing, plz make sure that virtualenvwrapper is correctly installed and you can execute its commands:  
`~$ workon`  
NOTE, **plz don't use *sudo* from here on unless explicitly prompted**.  
`~$ git clone https://github.com/fiberx/fiber.git`  
`~$ cd fiber`  
Setup the angr development environment specifically crafted for fiber:  
`~/fiber$ ./setup_angr_env.sh [dir_name] [venv_name]`

- *dir_name*:
Specify a directory and we'll put angr related files there.
- *venv_name*:
We will use a virtual python environment for fiber, specify its name here.

**NOTE**, should you be prompted to enter username/password for GitHub accounts during the execution of above script,
plz simply ignore that and just type *"Enter"*.  
It's time to install some required packages in the virtual env:  
`~/fiber$ workon [venv_name]`  
`(venv_name)~/fiber$ ./install_pkgs.sh`  
Now you are ready to use fiber scripts.  
As a test, you can run below command to see whether the signature can be shown w/o issues:  
`(venv_name)~/fiber$ python test_sig.py examples/sigs/CVE-2016-3866-sig-0`

**Before running any fiber scripts, remember to switch the virtual environment at first**:  
`workon [venv_name]`  
To exit the virtual environment:  
`deactivate`  

## 0x2 Picker

`(venv_name)~/fiber$ python pick_sig.py [patch_list] [reference kernel source] [output_file] [symbol_table,...]`

**Params**:  

- *patch_list*:
A file where each line specifies the path to a patch file. (eg. *examples/patch_list*)
- *reference kernel source*:
The path to the reference kernel source code root folder.
- *output_file*:
The results will be stored there. This file can then be used as "ext_list" for the translator (eg. *examples/ext_list*)
- *symbol_table*:
At least you should supply the symbol table for the reference kernel (eg. *examples/imgs/angler_img_20170513.sym*). However, if available you may also want to supply symbol table for the target kernel in order to help the picker to make better decisions (since target kernel symbol table can help to decide the function presence and inline situation in the target binary).

**Output**:  
Besides the *output_file* which stores the change site information, if necessary, the picker will generate another file *output_file_fail* which records the patches for which the picker fails to identify any suitable change sites. The possible reasons include: (1) the picker cannot match/locate the patch in the reference kernel source (2) the function changed by the patch cannot be found in the symbol tables (in this case the function will be inlined in the binary, currently we are unable to locate an inlined function in the binary.) (3) the patch has no suitable change sites to translate (eg. only change some variable definitions.) (4) fiber's own issues when doing the signature matching.

## 0x3 Translator

`(venv_name)~/fiber$ python ext_sig.py [ref_kernel_image] [ref_kernel_symbol_table] [ref_kernel_vmlinux] [ext_list] [output_dir]`  

**Params**:  

- *ref_kernel_image*:
The reference kernel zImage from which the binary signature will be generated. (eg. *examples/imgs/angler_img_20170513*)
- *ref_kernel_symbol_table*:
The symbol table for the reference kernel zImage (eg. examples/imgs/angler_img_20170513.sym). Since source code is available for the reference kernel, we can use "System.map" generated by the compiler.
- *ref_kernel_vmlinux*:
The "vmlinux" (generated by the compiler) for the reference kernel. We need this because it contains fine-grained DWARF debug information that can help to map source code lines to binary instructions. (Due to size limit we haven't included the vmlinux file for reference kernel in *example* folder, you can download it from here [*angler_img_20170513_vmlinux*](https://drive.google.com/file/d/1r16Q2yy-zpALJJWZg1gZBQNAplwDwdWC/view?usp=sharing))
- *ext_list*:
This file is generated by the picker. Each line specifies the information required to translate a binary signature. (eg. *examples/ext_list*)
- *output_dir*:
A directory path. All generated signatures will be stored there.

**Output**:  
Besides the generated signatures. The translator will also generate a *ext\_res\_[image]\_[timestamp]* file containing the time spent to generate each signature. (eg. *examples/ext\_res\_angler\_img\_20170513\_1528151764*)  

**NOTE**:  
The translator needs to use *addr2line* to read DWARF debug information, whose path is currently hardcoded in *ext_sig.py* (ADDR2LINE = '/path/to/addr2line'), plz make it right before executing this script.

## 0x4 Matcher

`(venv_name)~/fiber$ python match_sig.py [target_kernel_image] [target_kernel_symbol_table] [signature_list]`  

**Params**:  

- *target_kernel_image*: 
the kernel zImage that needs to be tested. (eg. *examples/imgs/image-G9300-160909*)
- *target_kernel_symbol_table*: 
the symbol table for the target kernel zImage (eg. *examples/imgs/image-G9300-160909.sym*). If source code is available, compiler can automatically generate the *System.map* file which can be used as the symbol table.
If not, we provide *tools/ext_sym* to extract the embedded symbol table from aarch64 linux kernel image (see the usage of this tool in section 0x5). Most Android kernel images should have such an embedded
symbol table, if not, you may want to use tools like *BinDiff* to inference the symbol table at first.
- *signature_list*: 
A file specifying the signatures that needs to be tested in the target kernel. This file can take one of two formats:  
**MODE 0**. Each line simply specifies the path to one binary signature (eg. *examples/sig_list_0*). This format is for binary signature validation, in this mode, the matcher will match every signature in the target kernel and in the end report the match count of each signature.  
**MODE 1** Each line specifies the signature path and the threshold match count (eg. *examples/sig_list_1*), besides, the signatures for a same patch are ranked by performance. This format is for the real patch presence test, the matcher will test each signature in the target kernel, if the match count surpasses the threshold value the signature will be regarded as matched. In the end the mathcer will report the presence of each patch (instead of match count for each signature) in the target kernel, 'P' means the patch is present, 'N' otherwise.

**Output**:  
The matcher will output the results to both the screen and an automatically generated file *match\_res\_[image]\_[timestamp]*.
As mentioned, different formats of *signature_list* will result in different outputs. If we are in mode 0 (binary signature validation), its outputs for unpatched and patched reference kernels (eg. *examples/match_res_angler_img_20160513_1528152449_m0* and *examples/match_res_angler_img_20170513_1528152555_m0*) can the be feed to *res_analyzer* (see section 5.2) which will then generate the mode 1 signature list (eg. *examples/sig_list_1*) that can be used to test real target kernels.

## 0x5 Auxilary Tools

### 5.1 tools/ext_sym

To extract the embedded symbol table from a kernel zImage.  
`~/fiber$ tools/ext_sym [image] [idc](optional) > output`  
**Params**:

- *image*:
The kernel zImage
- *idc*:
If you want, you can use `./ext_sym [image] 1` to generate an ".idc" file which is an IDA Pro script that can apply the symbol names when disassembling the kernel image.
Otherwise, a normal symbol table will be generated. (The format is like *System.map* file generated by the compiler).

### 5.2 tools/res_analyzer.py

Analyze the binary signature validation results and generate the *signature_list* that can be used to test real target kernels.  
`~/fiber$ python tools/res_analyzer.py [mode 0 match result for patched reference kernel] [mode 0 match result for unpatched reference kernel] > output`

As mentioned in section 0x4, the parameters are match results generated by the matcher in mode 0 (eg. *examples/match_res_angler_img_20160513_1528152449_m0* and *examples/match_res_angler_img_20170513_1528152555_m0*).

**Output**:  
A mode 1 signature list (as explained in section 0x4) will be generated. You need to check this file before using it with the matcher, if some lines in this file have a prefix '#', that means for that patch, all its signatures cannot differentiate the patched and unpatched reference kernels. In this case, you should use the picker to generate more candidate change sites, translating them to binary signatures and then validate them again. In the worst case, you can also manually inspect the patch and specify the change sites and related options manually.

### 5.3 test_sig.py

To view a binary signature.  
`(venv_name)~/fiber$ python test_sig.py [bin_sig]`  
**Params**:  
- *bin_sig*:
A binary signature generated by the translator. (eg. *examples/sigs/CVE-2016-3866-sig-0*)  

**Output**:  
The strcuture, node, root instructions and formulas of the signature will be shown on the screen.
