#!/bin/sh
rsync -crvz --rsh='ssh -i /Users/shenjunli/.ssh/gongjian_rsa' --delete-after --delete-excluded   _site/ blog_tech@182.92.222.156:tech/

