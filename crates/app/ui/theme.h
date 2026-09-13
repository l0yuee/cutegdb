#pragma once

#include "rust/cxx.h"

#include <QColor>
#include <QFont>
#include <QFontDatabase>
#include <QString>

// x64dbg's default colour scheme.
namespace theme {

inline const QColor Background{0xff, 0xf8, 0xf0};
inline const QColor Text{0x00, 0x00, 0x00};
inline const QColor Selection{0xc0, 0xc0, 0xc0};
inline const QColor AddressText{0x80, 0x80, 0x80};
inline const QColor LabelText{0xff, 0x00, 0x00};
inline const QColor CipBackground{0x00, 0x00, 0x00};
inline const QColor CipText{0xff, 0xff, 0xff};
inline const QColor BreakpointBackground{0xff, 0x00, 0x00};
inline const QColor BreakpointText{0x00, 0x00, 0x00};
inline const QColor HardwareBreakpoint{0xff, 0x80, 0x00};
inline const QColor DisabledBreakpoint{0xa0, 0xa0, 0xa0};
inline const QColor Bookmark{0x00, 0x80, 0xff};
inline const QColor BytesText{0x80, 0x80, 0x80};
inline const QColor CallBackground{0x00, 0xff, 0xff};
inline const QColor JumpBackground{0xff, 0xff, 0x00};
inline const QColor RetBackground{0x00, 0xff, 0xff};
inline const QColor PushPopText{0x00, 0x00, 0xff};
inline const QColor NopText{0x80, 0x80, 0x80};
inline const QColor Unreadable{0x80, 0x80, 0x80};
inline const QColor ChangedText{0xff, 0x00, 0x00};
inline const QColor JumpLine{0x80, 0x80, 0x80};
inline const QColor SelectedJumpLine{0xff, 0x00, 0x00};

inline QFont monospaceFont()
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    // Programming fonts with ligatures would draw "0x" as "0×" and merge "->" or "!=".
    font.setFeature(QFont::Tag("calt"), 0);
    font.setFeature(QFont::Tag("liga"), 0);
    return font;
}

} // namespace theme

inline QString qs(const rust::String& s)
{
    return QString::fromUtf8(s.data(), qsizetype(s.size()));
}
