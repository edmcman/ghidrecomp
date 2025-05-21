import pytest
from pathlib import Path

from ghidrecomp import decompile, get_parser
from ghidrecomp.decompile import get_bin_output_path, gen_proj_bin_name_from_path

def test_decomplie_ls(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", "--skip-cache"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 532
    assert len(decompilations) == 532
    assert output_path == expected_output_path
    assert compiler == 'unknown'
    assert lang_id == 'AARCH64:LE:64:v8A'
    assert len(callgraphs) == 0


def test_decomplie_ls_cached(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 532
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'unknown'
    assert lang_id == 'AARCH64:LE:64:v8A'
    assert len(callgraphs) == 0


def test_ctype_filter_ls(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", "--filter", "ctype", "--skip-cache"])

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 8
    assert len(decompilations) == 8
    assert len(callgraphs) == 0


def test_decomplie_afd(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}", "--skip-cache"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert (len(all_funcs) == 1275 or len(all_funcs) == 1273 or len(all_funcs) == 1172)
    assert (len(decompilations) == 1275 or len(decompilations) == 1273 or len(decompilations) == 1172)
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 0


def test_decomplie_afd_cached(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'afd.sys.10.0.22621.1415'

    args = parser.parse_args([f"{bin_path.absolute()}"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert (len(all_funcs) == 1275 or len(all_funcs) == 1273 or len(all_funcs) == 1172)
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'visualstudio:unknown'
    assert lang_id == 'x86:LE:64:default'
    assert len(callgraphs) == 0


def test_decomplie_ls_cppexport_exclude_func_decls(shared_datadir: Path):

    parser = get_parser()

    bin_path = shared_datadir / 'ls_aarch64'

    args = parser.parse_args([f"{bin_path.absolute()}", "--cppexport", "--exclude-func-decls"])

    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    expected_output_path = get_bin_output_path(args.output_path, bin_proj_name)

    all_funcs, decompilations, output_path, compiler, lang_id, callgraphs = decompile(args)

    assert len(all_funcs) == 532
    assert len(decompilations) == 0
    assert output_path == expected_output_path
    assert compiler == 'unknown'
    assert lang_id == 'AARCH64:LE:64:v8A'
    assert len(callgraphs) == 0

    c_file = expected_output_path / 'decomps' / f"{bin_path.name}.c"
    h_file = expected_output_path / 'decomps' / f"{bin_path.name}.h"

    assert c_file.exists()
    assert h_file.exists()

    with open(h_file, 'r') as f:
        header_content = f.read()
        assert 'void ' not in header_content
        assert 'int ' not in header_content
        assert 'char ' not in header_content
        assert 'float ' not in header_content
        assert 'double ' not in header_content
        assert 'struct ' not in header_content
        assert 'union ' not in header_content
        assert 'enum ' not in header_content
        assert 'typedef ' not in header_content
        assert 'extern ' not in header_content
        assert 'static ' not in header_content
        assert 'inline ' not in header_content
        assert 'register ' not in header_content
        assert 'volatile ' not in header_content
        assert 'const ' not in header_content
        assert 'unsigned ' not in header_content
        assert 'signed ' not in header_content
        assert 'short ' not in header_content
        assert 'long ' not in header_content
        assert 'void* ' not in header_content
        assert 'int* ' not in header_content
        assert 'char* ' not in header_content
        assert 'float* ' not in header_content
        assert 'double* ' not in header_content
        assert 'struct* ' not in header_content
        assert 'union* ' not in header_content
        assert 'enum* ' not in header_content
        assert 'typedef* ' not in header_content
        assert 'extern* ' not in header_content
        assert 'static* ' not in header_content
        assert 'inline* ' not in header_content
        assert 'register* ' not in header_content
        assert 'volatile* ' not in header_content
        assert 'const* ' not in header_content
        assert 'unsigned* ' not in header_content
        assert 'signed* ' not in header_content
        assert 'short* ' not in header_content
        assert 'long* ' not in header_content
