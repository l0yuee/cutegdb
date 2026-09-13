use cxx_qt_build::CxxQtBuilder;

fn main() {
    CxxQtBuilder::new()
        .qt_module("Gui")
        .qt_module("Widgets")
        .file("src/session.rs")
        .include_dir("ui")
        .cpp_files([
            "ui/app.cpp",
            "ui/mainwindow.h",
            "ui/mainwindow.cpp",
            "ui/shortcuts.cpp",
            "ui/baseview.h",
            "ui/baseview.cpp",
            "ui/disassemblyview.h",
            "ui/disassemblyview.cpp",
            "ui/registersview.h",
            "ui/registersview.cpp",
            "ui/stackview.h",
            "ui/stackview.cpp",
            "ui/dumpview.h",
            "ui/dumpview.cpp",
            "ui/cpuwidget.h",
            "ui/cpuwidget.cpp",
            "ui/views.h",
            "ui/views.cpp",
        ])
        .build();
    println!("cargo::rerun-if-changed=ui");
}
