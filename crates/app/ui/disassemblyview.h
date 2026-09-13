#pragma once

#include "baseview.h"
#include "cutegdb/src/session.cxxqt.h"

#include <QVector>
#include <cstdint>

class DisassemblyView : public BaseView {
    Q_OBJECT

public:
    explicit DisassemblyView(DebugSession* session, QWidget* parent = nullptr);

    std::uint64_t selectedAddress() const { return m_selection; }
    // Shows `address` at the top and selects it; `recordHistory` makes it reachable with '-'.
    void gotoAddress(std::uint64_t address, bool recordHistory);
    // Selects the instruction pointer, scrolling only when it is not already visible.
    void followCip(std::uint64_t cip);
    void reload();

signals:
    void selectionChanged(std::uint64_t address);
    // Shift+F2 on a line.
    void editBreakpointRequested(std::uint64_t address);
    // Space: `text` is the current instruction.
    void assembleRequested(std::uint64_t address, const QString& text);
    void commentRequested(std::uint64_t address);
    void labelRequested(std::uint64_t address);
    // Ctrl+E: `size` is the length of the selected instruction.
    void binaryEditRequested(std::uint64_t address, int size);
    // Ctrl+B.
    void searchPatternRequested(std::uint64_t address);
    void stringReferencesRequested(std::uint64_t address);
    // X: references to the selected address.
    void referencesRequested(std::uint64_t address);
    // G: graph of the function containing the address.
    void graphRequested(std::uint64_t address);

protected:
    void paintEvent(QPaintEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void scrollLines(int lines) override;

private:
    int sidebarWidth() const;
    QString selectedInstructionText() const;
    int selectedInstructionSize() const;
    int rowIndex(std::uint64_t address) const;
    void select(std::uint64_t address);
    void followBranch();
    void paintSidebar(QPainter& painter, int rows, std::uint64_t cip, bool paused);

    std::uint64_t m_top = 0;
    std::uint64_t m_selection = 0;
    bool m_loaded = false;
    rust::Vec<DisasmRow> m_rows;
    QVector<std::uint64_t> m_back;
    QVector<std::uint64_t> m_forward;
};
