#pragma once

#include "baseview.h"
#include "cutegdb/src/session.cxxqt.h"

#include <cstdint>

class DumpView : public BaseView {
    Q_OBJECT

public:
    explicit DumpView(DebugSession* session, QWidget* parent = nullptr);

    bool isLoaded() const { return m_loaded; }
    void gotoAddress(std::uint64_t address);
    // Forgets the address, so the next debuggee's first pause picks a fresh one.
    void reset();
    void reload();

protected:
    void paintEvent(QPaintEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void scrollLines(int lines) override;

private:
    static constexpr int BytesPerRow = 16;

    std::uint64_t m_top = 0;
    bool m_loaded = false;
    rust::Vec<std::int16_t> m_bytes;
};
