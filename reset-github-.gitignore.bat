git checkout main
git pull github-origin main
del .gitignore
copy .gitignore-github .gitignore
git rm -r --cached .
git add *
git commit -am "-"
git push github-origin main
