git checkout main
git pull origin main
del .gitignore
copy .gitignore-github .gitignore
git add *
git commit -am "-"
git push origin main