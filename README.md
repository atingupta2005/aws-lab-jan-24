# User Permissions management

## Set environment varials
```
export userpwd=""
export readonlyusersgroupname="readonlyusers"
export adminsgroupname="admins"
```

## Create groups
```
aws iam create-group --group-name $adminsgroupname
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --group-name $adminsgroupname
```

```
aws iam create-group --group-name $readonlyusersgroupname
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --group-name $readonlyusersgroupname
```

## Create Users
```
for ((i=1;i<=11;i++)); do
	export username="awslabuser$i"
	aws iam create-user --user-name $username
	aws iam create-login-profile --user-name $username --password $userpwd
done
```

## Add Users to Admin Group
```
for ((i=1;i<=11;i++)); do
	export username="awslabuser$i"
	aws iam add-user-to-group --user-name $username --group-name $admingroupname
done
```

## Remove users from Admin Group
```
for ((i=1;i<=11;i++)); do
	export username="awslabuser$i"
    aws iam remove-user-from-group --user-name $username --group-name $adminsgroupname
done
```

## Add users to Read Only Group
```
for ((i=1;i<=11;i++)); do
	export username="awslabuser$i"
    aws iam add-user-to-group --user-name $username --group-name $readonlyusersgroupname
done
```

## Delete User Login Profiles
```
for ((i=1;i<=11;i++)); do
	export username="awslabuser$i"
    aws iam delete-login-profile --user-name $username
done
```

## Delete users from group
```
for ((i=1;i<=11;i++)); do
	export username="awslabuser$i"
    aws iam remove-user-from-group --user-name $username --group-name $readonlyusersgroupname
    aws iam remove-user-from-group --user-name $username --group-name $adminsgroupname
done
```

## Delete Users
```
for ((i=1;i<=11;i++)); do
    export username="awslabuser$i"
    aws iam delete-user --user-name $username
done
```

## Delete Groups
```
aws iam list-attached-group-policies --group-name $readonlyusersgroupname
aws iam list-attached-group-policies --group-name $adminsgroupname
```

```
aws iam detach-group-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --group-name $adminsgroupname
```

```
aws iam detach-group-policy --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --group-name $readonlyusersgroupname
```

```
aws iam delete-group --group-name $readonlyusersgroupname
aws iam delete-group --group-name $adminsgroupname
```