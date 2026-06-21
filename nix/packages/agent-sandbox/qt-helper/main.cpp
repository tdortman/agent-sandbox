// Standalone Qt dialog helper for agent-sandbox policy prompts.
// No KDE or GTK dependencies — just Qt Widgets.
//
// Usage:
//   agent-sandbox-qt-dialog --title <window-title> --text <prompt-text> \
//       --option <label> [--option <label> ...]
//
// On user selection of an option, prints the exact label text to stdout and
// exits 0.  If the user closes the dialog or presses Cancel/Escape, exits
// nonzero with no output.

#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <QApplication>
#include <QDialog>
#include <QLabel>
#include <QPushButton>
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

int main(int argc, char* argv[]) {
    // Parse CLI args.
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

    auto* label = new QLabel(QString::fromStdString(text));
    label->setWordWrap(true);
    mainLayout->addWidget(label);

    auto* btnLayout = new QVBoxLayout();
    mainLayout->addLayout(btnLayout);

    // Track which option was selected; captured by lambda.
    std::string selected;

    for (const auto& opt : options) {
        auto* btn = new QPushButton(QString::fromStdString(opt));
        btn->setStyleSheet("text-align: left; padding: 6px 12px;");
        btnLayout->addWidget(btn);
        QObject::connect(btn, &QPushButton::clicked, [&dialog, &selected, opt]() {
            selected = opt;
            dialog.accept();
        });
    }

    // QDialog::reject is called on window close / Escape key.
    int ret = dialog.exec();

    if (ret != QDialog::Accepted || selected.empty()) {
        return EXIT_FAILURE;
    }

    std::printf("%s\n", selected.c_str());
    std::fflush(stdout);
    return EXIT_SUCCESS;
}
