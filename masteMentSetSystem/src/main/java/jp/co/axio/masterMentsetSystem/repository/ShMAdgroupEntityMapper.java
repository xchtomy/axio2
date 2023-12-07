package jp.co.axio.masterMentsetSystem.repository;

import org.apache.ibatis.annotations.Mapper;

import jp.co.axio.masterMentsetSystem.model.ShMAdgroupEntity;

@Mapper
public interface ShMAdgroupEntityMapper {

	ShMAdgroupEntity selectByExample(ShMAdgroupEntity entity);

    int update(ShMAdgroupEntity record);
}