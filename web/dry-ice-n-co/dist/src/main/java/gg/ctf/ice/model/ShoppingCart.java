package gg.ctf.ice.model;

import java.util.ArrayList;
import java.util.List;

public class ShoppingCart {
    private List<CartItem> items;
    private int balance;
    private String couponCode;
    private static final String VALID_COUPON = "SMILEICE";
    private static final int DISCOUNT_PERCENTAGE = 20;
    public static boolean boughtFlag = false;

    public ShoppingCart() {
        this.items = new ArrayList<>();
        this.balance = 100; // Initial balance of $100
        this.couponCode = null;
    }

    public List<CartItem> getItems() {
        return items;
    }

    public void addItem(CartItem item) {
        items.add(item);
    }

    public void removeItem(int index) {
        if (index >= 0 && index < items.size()) {
            items.remove(index);
        }
    }

    public int getBalance() {
        return balance;
    }

    public void setBalance(int balance) {
        this.balance = balance;
    }

    public String getCouponCode() {
        return couponCode;
    }

    public void setCouponCode(String couponCode) {
        this.couponCode = couponCode;
    }

    public boolean isCouponValid() {
        return VALID_COUPON.equals(couponCode);
    }

    public int getDiscountPercentage() {
        return isCouponValid() ? DISCOUNT_PERCENTAGE : 0;
    }

    public int getTotal() {
        int total = items.stream()
                .mapToInt(CartItem::getTotal)
                .sum();
        total = Math.abs(total);
        
        if (isCouponValid()) {
            total = (int)(total * (100.0 - (double)DISCOUNT_PERCENTAGE) / 100.0);
        }
        
        return total;
    }

    public boolean canAfford() {
        return balance >= getTotal();
    }

    public void purchase() {
        if (canAfford()) {
            balance -= getTotal();
            boolean hasFlag = items.size() == 1 && items.get(0).getName().equals("flag") && items.get(0).getQuantity() > 0;
            if (hasFlag) {
                boughtFlag = true;
            }
            
            items.clear();
            couponCode = null;
        }
    }
} 