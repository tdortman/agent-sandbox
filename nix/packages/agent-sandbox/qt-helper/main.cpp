// Standalone Qt dialog helper for agent-sandbox policy prompts.
// No KDE or GTK dependencies, just Qt Widgets.
//
// Usage:
//   agent-sandbox-qt-dialog --title <window-title> --text <prompt-text> \
//       --option <label> [--option <label> ...]
//
// On user selection of an option, prints the exact label text to stdout and
// exits 0. If the user closes the dialog or presses Cancel/Escape, exits
// nonzero with no output.

#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <QApplication>
#include <QDialog>
#include <QFrame>
#include <QPalette>
#include <QPushButton>
#include <QTextDocument>
#include <QTextEdit>
#include <QTextOption>
#include <QVBoxLayout>
#include <string>
#include <vector>

static void usage(FILE* fp, const char* argv0) {
    fprintf(
        fp,
        "Usage: %s --title <title> --text <text> "
        "--option <label> [--option <label> ...]\n",
        argv0
    );
    std::exit(fp == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

// Build a read-only text widget that reflows dynamically as the dialog is
// resized. WrapAtWordBoundaryOrAnywhere prefers word boundaries but breaks
// inside unbroken tokens (paths, base64 blobs) when a single word is wider
// than the widget, so nothing overflows even on narrow windows.
// Text widget sized to exactly fit its content so the dialog is only as tall as
// the text needs. QTextEdit's sizeHint and minimumSizeHint are content-agnostic
// (a ~3-line floor), so without these overrides a one-line prompt left the
// dialog tall with empty space above/below the text and below the buttons.
// hasHeightForWidth + heightForWidth let the layout size the dialog to the text
// at any width; minimumSizeHint lifts the built-in floor so a single line is one
// line tall. QTextEdit already relays the document to the viewport on resize, so
// wrapped text (long domains/paths/commands) reflows without extra plumbing.
class FitText : public QTextEdit {
   public:
    explicit FitText(const QString& text, QWidget* parent = nullptr) : QTextEdit(text, parent) {
        // Content always fits, so scrollbars would just steal layout width.
        setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    }

    bool hasHeightForWidth() const override {
        return true;
    }

    // QAbstractScrollArea floors the widget at ~3 lines via minimumSizeHint;
    // the real minimum is the content height, so report 0 and let
    // heightForWidth drive the size.
    QSize minimumSizeHint() const override {
        return QSize(QTextEdit::minimumSizeHint().width(), 0);
    }

    int heightForWidth(int w) const override {
        const int inner = w - 2 * frameWidth();
        if (inner <= 0) {
            return -1;
        }
        auto* doc = const_cast<QTextDocument*>(document());
        doc->setTextWidth(qreal(inner));
        return qCeil(doc->size().height()) + 2 * frameWidth();
    }
};

int main(int argc, char* argv[]) {
    std::string title;
    std::string text;
    std::vector<std::string> options;

    enum { OPT_TITLE = 256, OPT_TEXT, OPT_OPTION };

    static struct option long_opts[] = {
        {"title", required_argument, nullptr, OPT_TITLE},
        {"text", required_argument, nullptr, OPT_TEXT},
        {"option", required_argument, nullptr, OPT_OPTION},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "h", long_opts, nullptr)) != -1) {
        switch (ch) {
            case OPT_TITLE:
                title = optarg;
                break;
            case OPT_TEXT:
                text = optarg;
                break;
            case OPT_OPTION:
                options.emplace_back(optarg);
                break;
            case 'h':
                usage(stdout, argv[0]);
                break;
            default:
                usage(stderr, argv[0]);
        }
    }

    if (title.empty() || text.empty() || options.empty()) {
        usage(stderr, argv[0]);
    }

    QApplication app(argc, argv);
    QApplication::setApplicationName("agent-sandbox");

    QDialog dialog;
    dialog.setWindowTitle(QString::fromStdString(title));
    dialog.setMinimumWidth(400);

    auto* mainLayout = new QVBoxLayout(&dialog);

    // Read-only text widget sized to exactly fit its content (see FitText).
    auto* prompt = new FitText(QString::fromStdString(text), &dialog);
    prompt->setReadOnly(true);
    prompt->setFrameShape(QFrame::NoFrame);
    prompt->setFocusPolicy(Qt::NoFocus);

    // Use the dialog's default text palette and font so the prompt looks like
    // a label, not an editable field.
    QPalette promptPalette = prompt->palette();
    promptPalette.setColor(QPalette::Base, dialog.palette().color(QPalette::Window));
    prompt->setPalette(promptPalette);
    prompt->setFont(dialog.font());
    prompt->setLineWrapMode(QTextEdit::WidgetWidth);
    prompt->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    mainLayout->addWidget(prompt);

    auto* btnLayout = new QVBoxLayout();
    mainLayout->addLayout(btnLayout);

    // Track which option was selected. Captured by the click lambda.
    std::string selected;

    for (const auto& opt : options) {
        auto* btn = new QPushButton(QString::fromStdString(opt), &dialog);
        btn->setStyleSheet("text-align: left; padding: 6px 12px;");
        // Comfortable height so the label clears the frame
        // (12 = stylesheet vertical padding, 8 = frame slack).
        btn->setMinimumHeight(btn->fontMetrics().height() + 12 + 8);
        btnLayout->addWidget(btn);
        QObject::connect(btn, &QPushButton::clicked, [&dialog, &selected, opt]() {
            selected = opt;
            dialog.accept();
        });
    }

    // Pin the prompt's minimum height to its real wrapped height. A top-level
    // QDialog sizes itself from the layout's sizeHint, which under-counts a
    // height-for-width child by ~1 wrapped line; that left the dialog a hair
    // too short, so the layout crushed the inter-button spacing by a different
    // amount per prompt stage, making the gaps look inconsistent. Measured
    // with a throwaway QTextDocument at the dialog's actual width; setting the
    // prompt's minimum (not the dialog's) keeps height-for-width sizing intact.
    {
        const int dlgW = qMax(dialog.sizeHint().width(), dialog.minimumWidth());
        const int contentW =
            dlgW - mainLayout->contentsMargins().left() - mainLayout->contentsMargins().right();
        QTextDocument measureDoc(QString::fromStdString(text));
        measureDoc.setDefaultFont(prompt->font());
        QTextOption to = measureDoc.defaultTextOption();
        to.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
        measureDoc.setDefaultTextOption(to);
        measureDoc.setTextWidth(qreal(contentW));
        prompt->setMinimumHeight(qCeil(measureDoc.size().height()));
    }

    // Focus the first option so Enter accepts the default.
    if (btnLayout->itemAt(0) != nullptr) {
        if (auto* firstBtn = btnLayout->itemAt(0)->widget()) {
            firstBtn->setFocus();
        }
    }

    // QDialog::reject is called on window close or Escape key.
    int ret = dialog.exec();

    if (ret != QDialog::Accepted || selected.empty()) {
        return EXIT_FAILURE;
    }

    std::printf("%s\n", selected.c_str());
    std::fflush(stdout);
    return EXIT_SUCCESS;
}
