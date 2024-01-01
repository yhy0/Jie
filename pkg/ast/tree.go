package ast

import "sort"

type Node struct {
    Key      int
    Value    NodeValue
    Children []*Node
}

func (n *Node) Search(key int) (*Node, bool) {
    for _, child := range n.Children {
        if child.Key == key {
            return child, true
        } else if child.Key > key {
            return child.Search(key)
        }
    }
    return nil, false
}

// Insert 使用二分查找实现节点插入操作 https://github.com/wrenchonline/glint/issues/12
func (n *Node) Insert(key int, tagName string, Content *string, Attributes *[]*Attribute) {
    if n.Length() != 0 {
        idx := sort.Search(len(n.Children), func(i int) bool { return n.Children[i].Key >= key })
        if idx < len(n.Children) && n.Children[idx].Key == key {
            // 如果指定索引值已存在，则进行合并操作或抛出异常等处理
        } else {
            node := &Node{Key: key, Value: NodeValue{TagName: tagName, Content: *Content, Attributes: *Attributes}}
            n.Children = append(n.Children, nil)
            copy(n.Children[idx+1:], n.Children[idx:])
            n.Children[idx] = node
        }
    } else {
        n.Children = append(n.Children, &Node{Key: key, Value: NodeValue{TagName: tagName, Content: *Content, Attributes: *Attributes}})
    }
}

func (n *Node) Delete(key int) bool {
    for i, child := range n.Children {
        if child.Key == key {
            n.Children = append(n.Children[:i], n.Children[i+1:]...)
            return true
        } else if child.Key > key {
            return child.Delete(key)
        }
    }
    return false
}

func (n *Node) Max() (*Node, bool) {
    maxkey := n.Key

    for _, child := range n.Children {
        if child.Key > maxkey {
            maxkey = child.Key
        }
    }
    maxnode, b := n.Search(maxkey)
    if !b {
        return nil, false
    }
    return maxnode, true
}

func (n *Node) Set(node *Node) {
    n.Insert(node.Key, node.Value.TagName, &node.Value.Content, &node.Value.Attributes)
}

func (n *Node) Length() int {
    return len(n.Children)
}

func (n *Node) Clear() {
    n.Children = n.Children[:0]
    n.Key = 0
    n.Value = NodeValue{}
}
