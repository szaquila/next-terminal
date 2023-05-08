package repository

import (
	"context"
	"strconv"

	"next-terminal/server/model"
)

var UserRepository = new(userRepository)

type userRepository struct {
	baseRepository
}

func (r userRepository) FindAll(c context.Context) (o []model.User, err error) {
	err = r.GetDB(c).Find(&o).Error
	return
}

func (r userRepository) Find(c context.Context, pageIndex, pageSize int, username, nickname, mail, online, loginPolicyId, order, field string) (o []model.UserForPage, total int64, err error) {
	db := r.GetDB(c).Table("users").Select("users.id,users.username,users.nickname,users.mail,users.online,users.created,users.type,users.status,users.source, users.totp_secret")
	dbCounter := r.GetDB(c).Table("users")

	if loginPolicyId != "" {
		db = db.Joins("left join login_policies_ref as ref on users.id = ref.user_id")
		dbCounter = dbCounter.Joins("left join login_policies_ref as ref on users.id = ref.user_id")

		db = db.Where("ref.login_policy_id = ?", loginPolicyId)
		dbCounter = dbCounter.Where("ref.login_policy_id = ?", loginPolicyId)
	}

	if len(username) > 0 {
		db = db.Where("users.username like ?", "%"+username+"%")
		dbCounter = dbCounter.Where("username like ?", "%"+username+"%")
	}

	if len(nickname) > 0 {
		db = db.Where("users.nickname like ?", "%"+nickname+"%")
		dbCounter = dbCounter.Where("nickname like ?", "%"+nickname+"%")
	}

	if len(mail) > 0 {
		db = db.Where("users.mail like ?", "%"+mail+"%")
		dbCounter = dbCounter.Where("mail like ?", "%"+mail+"%")
	}

	if online != "" {
		_online, err := strconv.ParseBool(online)
		if err != nil {
			return nil, 0, err
		}
		db = db.Where("users.online = ?", _online)
		dbCounter = dbCounter.Where("users.online = ?", _online)
	}

	err = dbCounter.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	if order == "ascend" {
		order = "asc"
	} else {
		order = "desc"
	}

	if field == "username" {
		field = "username"
	} else if field == "nickname" {
		field = "nickname"
	} else {
		field = "created"
	}

	err = db.Order("users." + field + " " + order).Find(&o).Offset((pageIndex - 1) * pageSize).Limit(pageSize).Error
	if o == nil {
		o = make([]model.UserForPage, 0)
	}

	for i := 0; i < len(o); i++ {
		if o[i].TOTPSecret == "" || o[i].TOTPSecret == "-" {
			o[i].TOTPSecret = "0"
			// } else {
			// 	o[i].TOTPSecret = "1"
		}
	}
	return
}

func (r userRepository) FindById(c context.Context, id string) (o model.User, err error) {
	err = r.GetDB(c).Where("id = ?", id).First(&o).Error
	return
}

func (r userRepository) FindByUsername(c context.Context, username string) (o model.User, err error) {
	err = r.GetDB(c).Where("username = ?", username).First(&o).Error
	return
}

func (r userRepository) ExistByUsername(c context.Context, username string) (exist bool, err error) {
	user := model.User{}
	var count uint64
	err = r.GetDB(c).Table(user.TableName()).Select("count(*)").
		Where("username = ?", username).
		Find(&count).
		Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r userRepository) ExistById(c context.Context, id string) (exist bool, err error) {
	user := model.User{}
	var count uint64
	err = r.GetDB(c).Table(user.TableName()).Select("count(*)").
		Where("id = ?", id).
		Find(&count).
		Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r userRepository) FindOnlineUsers(c context.Context) (o []model.User, err error) {
	err = r.GetDB(c).Where("online = ?", true).Find(&o).Error
	return
}

func (r userRepository) Create(c context.Context, o *model.User) error {
	return r.GetDB(c).Create(o).Error
}

func (r userRepository) Update(c context.Context, o *model.User) error {
	return r.GetDB(c).Updates(o).Error
}

func (r userRepository) UpdateOnlineByUsername(c context.Context, username string, online bool) error {
	sql := "update users set online = ? where username = ?"
	return r.GetDB(c).Exec(sql, online, username).Error
}

func (r userRepository) DeleteById(c context.Context, id string) error {
	return r.GetDB(c).Where("id = ?", id).Delete(&model.User{}).Error
}

func (r userRepository) DeleteBySource(c context.Context, source string) error {
	return r.GetDB(c).Where("source = ?", source).Delete(&model.User{}).Error
}

func (r userRepository) CountOnlineUser(c context.Context) (total int64, err error) {
	err = r.GetDB(c).Where("online = ?", true).Find(&model.User{}).Count(&total).Error
	return
}

func (r userRepository) Count(c context.Context) (total int64, err error) {
	err = r.GetDB(c).Find(&model.User{}).Count(&total).Error
	return
}
