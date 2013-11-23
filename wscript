#! /usr/bin/env python
# encoding: utf-8

APPNAME = 'Lurker'
VERSION = "0.1.0"

target_name = 'lurker'
test_cmd = 'lurker_test'
main_lib = ['swarm']

import sys
import os
import platform
import subprocess
import time
import re

top = '.'
out = 'build'
test_fname = os.path.join (out, test_cmd)

def options(opt):
    opt.load ('compiler_cxx')
    opt.add_option ('--enable-debug',
                    action='store_true', dest='debug',
                    help='enable debug options')
    opt.add_option ('--enable-profile',
                    action='store_true', dest='profile',
                    help='enable profiling options')
    opt.add_option ('--enable-test',
                    action='store_true', dest='test',
                    help='enable test suite')
    opt.add_option ('--libdir', dest='libdir',
                    action='store', default=None)
    opt.add_option ('--incdir', dest='incdir',
                    action='store', default=None)

def configure(conf):
    global main_lib
    lib_list = main_lib

    # ----------------------------------
    # check clang
    try:
        has_clang = True
        conf.find_program ('clang++')
    except Exception, e:
        has_clang = False

    if ('Darwin' == platform.system() and 
        os.environ.get('CXX') is None and 
        has_clang):
        conf.env.append_value ('CXX', 'clang++')

    # ----------------------------------
    # c++ flags setting
    cxxflags = ['-Wall', '-std=c++0x']
    linkflags = []

    if conf.options.debug:
        cxxflags.extend (['-O0', '-g', '-pg'])
        linkflags.extend (['-g', '-pg'])
    else:
        cxxflags.extend (['-O2'])    

    if conf.options.incdir is not None: 
        cxxflags.append ('-I{0}'.format (os.path.abspath (conf.options.incdir)))
    if conf.options.libdir is not None: 
        linkflags.append ('-L{0}'.format (os.path.abspath (conf.options.libdir)))

    conf.env.append_value('CXXFLAGS', cxxflags) 
    conf.env.append_value('INCLUDES', ['.', '%s/include' % conf.env.PREFIX])
    conf.env.append_value('LINKFLAGS', linkflags)
        
    # ----------------------------------
    # compiler and libraries
    conf.load('compiler_cxx')
    for libname in lib_list: 
        if libname == 'swarm': conf.check_cxx(lib = libname)
        else: conf.check_cxx(lib = libname)

    if conf.options.test:
        p = subprocess.Popen('gtest-config --libdir', shell=True, stdout=subprocess.PIPE)
        gtest_libpath = p.stdout.readline().strip ()
        p.wait ()
        conf.env.append_value('LIBDIR', gtest_libpath)
        conf.check_cxx(lib = 'gtest', args = ['-lpthread'])

    conf.env.store('config.log')    
    conf.env.test = True if conf.options.test else False

def build(bld):
    def get_src_list(d):
        src = []
        for (root, dirs, files) in os.walk(d):
            for f in files:
                if f.endswith('.cc'): src.append(os.path.join(root, f))
        return src

    libs = ['swarm']
    bld.program(features = 'cxxprogram',
                source = get_src_list('src'),
                target = target_name,
                lib = libs,
                # includes = [inc_dir],
                LIBDIR = [os.path.join (bld.env.PREFIX, 'lib')],
                rpath = [os.path.join (bld.env.PREFIX, 'lib'),
                         os.path.join (bld.path.abspath(), 'build', '..', 'src')])

    bld.program(features = 'cxxprogram',
                source = get_src_list('test'),
                target = test_cmd,
                lib = libs,
                # includes = [inc_dir],
                LIBDIR = [os.path.join (bld.env.PREFIX, 'lib')],
                rpath = [os.path.join (bld.env.PREFIX, 'lib'),
                         os.path.join (bld.path.abspath(), 'build', '..', 'src')])
    



def shutdown(ctx):
    pass
