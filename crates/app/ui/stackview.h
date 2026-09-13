#pragma once

#include "baseview.h"
#include "cutegdb/src/session.cxxqt.h"

#include <cstdint>

class StackView : public BaseView {
    Q_OBJECT

public:
    explicit StackView(DebugSession* session, QWidget* parent = nullptr);

    void gotoAddress(std::uint64_t address);
    // Keeps the stack pointer visible, scrolling only when it is outside the view.
    void followStackPointer(std::uint64_t sp);
    void reload();

protected:
    void paintEvent(QPaintEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void scrollLines(int lines) override;

private:
    std::uint64_t m_top = 0;
    bool m_loaded = false;
    rust::Vec<StackRow> m_rows;
};
