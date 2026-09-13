#include "dumpview.h"
#include "theme.h"

#include <QKeyEvent>
#include <QPainter>

DumpView::DumpView(DebugSession* session, QWidget* parent)
    : BaseView(session, parent)
{
}

void DumpView::gotoAddress(std::uint64_t address)
{
    m_top = address;
    m_loaded = true;
    reload();
}

void DumpView::reset()
{
    m_loaded = false;
    m_bytes.clear();
    viewport()->update();
}

void DumpView::reload()
{
    if (!m_loaded)
        return;
    m_bytes = session()->readMemory(m_top, visibleRows() * BytesPerRow);
    viewport()->update();
}

void DumpView::scrollLines(int lines)
{
    if (!m_loaded)
        return;
    m_top += std::uint64_t(std::int64_t(lines) * BytesPerRow);
    reload();
}

void DumpView::keyPressEvent(QKeyEvent* event)
{
    switch (event->key()) {
    case Qt::Key_Up:
        scrollLines(-1);
        break;
    case Qt::Key_Down:
        scrollLines(1);
        break;
    case Qt::Key_PageUp:
        scrollLines(-visibleRows());
        break;
    case Qt::Key_PageDown:
        scrollLines(visibleRows());
        break;
    default:
        BaseView::keyPressEvent(event);
    }
}

void DumpView::resizeEvent(QResizeEvent* event)
{
    BaseView::resizeEvent(event);
    reload();
}

void DumpView::paintEvent(QPaintEvent*)
{
    QPainter p(viewport());
    p.setFont(font());
    p.fillRect(viewport()->rect(), theme::Background);
    if (!m_loaded)
        return;

    const int rh = rowHeight();
    const int cw = charWidth();
    const int addressWidth = cw * (session()->pointerSize() * 2 + 2);
    const int hexX = addressWidth;
    const int asciiX = hexX + BytesPerRow * 3 * cw + cw;
    const int rows = int(m_bytes.size()) / BytesPerRow;

    for (int r = 0; r < rows; ++r) {
        const int y = r * rh;
        p.setPen(theme::AddressText);
        p.drawText(QRect(cw / 2, y, addressWidth, rh), Qt::AlignVCenter | Qt::AlignLeft,
            session()->formatAddress(m_top + std::uint64_t(r * BytesPerRow)));
        QString ascii;
        for (int c = 0; c < BytesPerRow; ++c) {
            const std::int16_t byte = m_bytes[std::size_t(r * BytesPerRow + c)];
            const QRect cell(hexX + c * 3 * cw, y, 3 * cw, rh);
            if (byte < 0) {
                p.setPen(theme::Unreadable);
                p.drawText(cell, Qt::AlignVCenter | Qt::AlignLeft, QStringLiteral("??"));
                ascii += QLatin1Char('?');
            } else {
                p.setPen(theme::Text);
                p.drawText(cell, Qt::AlignVCenter | Qt::AlignLeft, QStringLiteral("%1").arg(byte, 2, 16, QLatin1Char('0')).toUpper());
                ascii += (byte >= 0x20 && byte < 0x7f) ? QChar(byte) : QLatin1Char('.');
            }
        }
        p.setPen(theme::Text);
        p.drawText(QRect(asciiX, y, viewport()->width() - asciiX, rh), Qt::AlignVCenter | Qt::AlignLeft, ascii);
    }
}
