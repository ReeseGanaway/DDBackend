package com.ganaway.backend.model;

import javax.persistence.*;

@Entity
@Table(name="characters")
public class Character {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int charID;
    @Column(name= "name", nullable = false)
    private String name;
    @Column(name= "max_hp", nullable = false)
    private int maxHp;
    @Column(name= "max_dmg", nullable = false)
    private int maxDmg;

    @Column(name="max_move_range", nullable = false)
    private int maxMoveRange;
    @Column(name= "max_attack_range", nullable = false)
    private int maxAttackRange;
    @Column(name= "spriteSheet", nullable = false)
    private String spriteSheet;
    @Column(name= "icon", nullable = false)
    private String icon;
    @Column(name = "level", nullable = false)
    private int level;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "userID", nullable = false)
    private User user;

    public Character() {
    }

    public Character(String name, int maxHp, int maxDmg, int maxMoveRange, int maxAttackRange, String spriteSheet, String icon, int level) {

        this.name = name;
        this.maxHp = maxHp;
        this.maxDmg = maxDmg;
        this.maxMoveRange = maxMoveRange;
        this.maxAttackRange = maxAttackRange;
        this.spriteSheet = spriteSheet;
        this.icon = icon;

    }

    public int getCharID() {
        return charID;
    }

    public void setCharID(int charID) {
        this.charID = charID;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getMaxHp() {
        return maxHp;
    }

    public void setMaxHp(int maxHp) {
        this.maxHp = maxHp;
    }

    public int getMaxDmg() {
        return maxDmg;
    }

    public void setMaxDmg(int maxDmg) {
        this.maxDmg = maxDmg;
    }

    public int getMaxMoveRange() {
        return maxMoveRange;
    }

    public void setMaxMoveRange(int maxMoveRange) {
        this.maxMoveRange = maxMoveRange;
    }

    public int getMaxAttackRange() {
        return maxAttackRange;
    }

    public void setMaxAttackRange(int maxAttackRange) {
        this.maxAttackRange = maxAttackRange;
    }

    public String getSpriteSheet() {
        return spriteSheet;
    }

    public void setSpriteSheet(String spriteSheet) {
        this.spriteSheet = spriteSheet;
    }

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }
}
